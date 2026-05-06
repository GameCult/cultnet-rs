use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use cultcache_rs::CultCache;
use cultcache_rs::CultCacheEnvelope;
use cultcache_rs::DatabaseEntry;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::CultNetDocumentMutationContract;
use crate::CultNetDocumentRecord;
use crate::CultNetMessage;
use crate::CultNetRawDocumentRecord;
use crate::CultNetRawPayloadEncoding;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CultNetDocumentPutOptions {
    pub stored_at: Option<String>,
    pub source_runtime_id: Option<String>,
    pub source_agent_id: Option<String>,
    pub source_role: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CultNetDocumentBinding {
    pub document_type: String,
    pub payload_schema_version: Option<String>,
    pub mutation_contract: Option<CultNetDocumentMutationContract>,
}

impl CultNetDocumentBinding {
    pub fn for_entry<T: DatabaseEntry>(payload_schema_version: impl Into<Option<String>>) -> Self {
        Self {
            document_type: T::TYPE.to_string(),
            payload_schema_version: payload_schema_version.into(),
            mutation_contract: None,
        }
    }

    pub fn with_mutation_contract(mut self, contract: CultNetDocumentMutationContract) -> Self {
        self.mutation_contract = Some(contract);
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct CultNetDocumentRegistry {
    bindings: BTreeMap<String, CultNetDocumentBinding>,
}

impl CultNetDocumentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, binding: CultNetDocumentBinding) -> &mut Self {
        self.bindings.insert(binding.document_type.clone(), binding);
        self
    }

    pub fn binding(&self, document_type: &str) -> Option<&CultNetDocumentBinding> {
        self.bindings.get(document_type)
    }

    pub fn mutation_contracts(&self) -> Vec<CultNetDocumentMutationContract> {
        self.bindings
            .values()
            .filter_map(|binding| binding.mutation_contract.clone())
            .collect()
    }

    pub fn create_document_put_message<T>(
        &self,
        message_id: impl Into<String>,
        document_key: impl Into<String>,
        value: &T,
        options: CultNetDocumentPutOptions,
    ) -> Result<CultNetMessage>
    where
        T: DatabaseEntry + Serialize + DeserializeOwned,
    {
        let binding = self.require_binding(T::TYPE)?;
        let payload = serde_json::to_value(round_trip_typed(value)?)?;
        Ok(CultNetMessage::DocumentPut {
            message_id: message_id.into(),
            document: CultNetDocumentRecord {
                document_type: binding.document_type.clone(),
                document_key: document_key.into(),
                stored_at: options.stored_at.unwrap_or_else(now_utc_second),
                payload_schema_version: binding.payload_schema_version.clone(),
                payload,
                source_runtime_id: options.source_runtime_id,
                source_agent_id: options.source_agent_id,
                source_role: options.source_role,
                tags: options.tags,
            },
        })
    }

    pub fn create_document_delete_message(
        &self,
        message_id: impl Into<String>,
        document_type: impl Into<String>,
        document_key: impl Into<String>,
    ) -> CultNetMessage {
        CultNetMessage::DocumentDelete {
            message_id: message_id.into(),
            document_type: document_type.into(),
            document_key: document_key.into(),
        }
    }

    pub fn create_raw_document_put_message_from_envelope(
        &self,
        message_id: impl Into<String>,
        envelope: &CultCacheEnvelope,
    ) -> Result<CultNetMessage> {
        Ok(CultNetMessage::DocumentPutRaw {
            message_id: message_id.into(),
            document: self.raw_document_record_from_envelope(envelope)?,
        })
    }

    pub fn create_snapshot_response(
        &self,
        cache: &CultCache,
        message_id: impl Into<String>,
        document_types: Option<&[String]>,
        document_keys: Option<&[String]>,
    ) -> Result<CultNetMessage> {
        let requested_types = document_types.map(|items| items.iter().collect::<BTreeSet<_>>());
        let requested_keys = document_keys.map(|items| items.iter().collect::<BTreeSet<_>>());
        let mut documents = Vec::new();
        for envelope in cache.snapshot() {
            if requested_types
                .as_ref()
                .is_some_and(|types| !types.contains(&envelope.r#type))
            {
                continue;
            }
            if requested_keys
                .as_ref()
                .is_some_and(|keys| !keys.contains(&envelope.key))
            {
                continue;
            }
            documents.push(self.document_record_from_envelope(&envelope)?);
        }
        Ok(CultNetMessage::SnapshotResponse {
            message_id: message_id.into(),
            documents,
        })
    }

    pub fn create_raw_snapshot_response(
        &self,
        cache: &CultCache,
        message_id: impl Into<String>,
        document_types: Option<&[String]>,
        document_keys: Option<&[String]>,
    ) -> Result<CultNetMessage> {
        let requested_types = document_types.map(|items| items.iter().collect::<BTreeSet<_>>());
        let requested_keys = document_keys.map(|items| items.iter().collect::<BTreeSet<_>>());
        let mut documents = Vec::new();
        for envelope in cache.snapshot() {
            if requested_types
                .as_ref()
                .is_some_and(|types| !types.contains(&envelope.r#type))
            {
                continue;
            }
            if requested_keys
                .as_ref()
                .is_some_and(|keys| !keys.contains(&envelope.key))
            {
                continue;
            }
            documents.push(self.raw_document_record_from_envelope(&envelope)?);
        }
        Ok(CultNetMessage::SnapshotResponseRaw {
            message_id: message_id.into(),
            documents,
        })
    }

    pub fn apply_document_put_message<T>(
        &self,
        cache: &mut CultCache,
        message: &CultNetMessage,
    ) -> Result<T>
    where
        T: DatabaseEntry + Serialize + DeserializeOwned,
    {
        let CultNetMessage::DocumentPut { document, .. } = message else {
            return Err(anyhow!("expected cultnet.document_put.v0"));
        };
        if document.document_type != T::TYPE {
            return Err(anyhow!(
                "document type {:?} does not match registered Rust type {:?}",
                document.document_type,
                T::TYPE
            ));
        }
        self.require_binding(T::TYPE)?;
        let value: T = serde_json::from_value(document.payload.clone()).with_context(|| {
            format!(
                "failed to decode CultNet payload {:?} as {}",
                T::TYPE,
                T::SCHEMA_NAME
            )
        })?;
        cache.put(&document.document_key, &value)
    }

    pub fn apply_document_delete_message<T>(
        &self,
        cache: &mut CultCache,
        message: &CultNetMessage,
    ) -> Result<bool>
    where
        T: DatabaseEntry,
    {
        let CultNetMessage::DocumentDelete {
            document_type,
            document_key,
            ..
        } = message
        else {
            return Err(anyhow!("expected cultnet.document_delete.v0"));
        };
        if document_type != T::TYPE {
            return Err(anyhow!(
                "document type {:?} does not match registered Rust type {:?}",
                document_type,
                T::TYPE
            ));
        }
        self.require_binding(T::TYPE)?;
        cache.delete::<T>(document_key)
    }

    pub fn apply_raw_document_put_message<T>(
        &self,
        cache: &mut CultCache,
        message: &CultNetMessage,
    ) -> Result<T>
    where
        T: DatabaseEntry + Serialize + DeserializeOwned,
    {
        let CultNetMessage::DocumentPutRaw { document, .. } = message else {
            return Err(anyhow!("expected cultnet.document_put_raw.v0"));
        };
        if document.document_type != T::TYPE {
            return Err(anyhow!(
                "document type {:?} does not match registered Rust type {:?}",
                document.document_type,
                T::TYPE
            ));
        }
        self.require_binding(T::TYPE)?;
        cache.put_envelope::<T>(CultCacheEnvelope {
            key: document.document_key.clone(),
            r#type: document.document_type.clone(),
            payload: document.payload.clone(),
            stored_at: document.stored_at.clone(),
        })
    }

    pub fn apply_snapshot_response<T>(
        &self,
        cache: &mut CultCache,
        response: &CultNetMessage,
    ) -> Result<Vec<T>>
    where
        T: DatabaseEntry + Serialize + DeserializeOwned,
    {
        let CultNetMessage::SnapshotResponse { documents, .. } = response else {
            return Err(anyhow!("expected cultnet.snapshot_response.v0"));
        };
        let mut applied = Vec::new();
        for document in documents {
            if document.document_type != T::TYPE {
                continue;
            }
            applied.push(self.apply_document_put_message::<T>(
                cache,
                &CultNetMessage::DocumentPut {
                    message_id: "snapshot-apply".to_string(),
                    document: document.clone(),
                },
            )?);
        }
        Ok(applied)
    }

    pub fn apply_raw_snapshot_response<T>(
        &self,
        cache: &mut CultCache,
        response: &CultNetMessage,
    ) -> Result<Vec<T>>
    where
        T: DatabaseEntry + Serialize + DeserializeOwned,
    {
        let CultNetMessage::SnapshotResponseRaw { documents, .. } = response else {
            return Err(anyhow!("expected cultnet.snapshot_response_raw.v0"));
        };
        let mut applied = Vec::new();
        for document in documents {
            if document.document_type != T::TYPE {
                continue;
            }
            applied.push(self.apply_raw_document_put_message::<T>(
                cache,
                &CultNetMessage::DocumentPutRaw {
                    message_id: "snapshot-apply-raw".to_string(),
                    document: document.clone(),
                },
            )?);
        }
        Ok(applied)
    }

    fn document_record_from_envelope(
        &self,
        envelope: &CultCacheEnvelope,
    ) -> Result<CultNetDocumentRecord<Value>> {
        let binding = self.require_binding(&envelope.r#type)?;
        let payload: Value = rmp_serde::from_slice(&envelope.payload).with_context(|| {
            format!(
                "failed to decode CultCache envelope {:?} at {:?} as generic CultNet payload",
                envelope.r#type, envelope.key
            )
        })?;
        Ok(CultNetDocumentRecord {
            document_type: envelope.r#type.clone(),
            document_key: envelope.key.clone(),
            stored_at: envelope.stored_at.clone(),
            payload_schema_version: binding.payload_schema_version.clone(),
            payload,
            source_runtime_id: None,
            source_agent_id: None,
            source_role: None,
            tags: None,
        })
    }

    fn raw_document_record_from_envelope(
        &self,
        envelope: &CultCacheEnvelope,
    ) -> Result<CultNetRawDocumentRecord> {
        let binding = self.require_binding(&envelope.r#type)?;
        Ok(CultNetRawDocumentRecord {
            document_type: envelope.r#type.clone(),
            document_key: envelope.key.clone(),
            stored_at: envelope.stored_at.clone(),
            payload_schema_version: binding.payload_schema_version.clone(),
            payload_encoding: CultNetRawPayloadEncoding::Messagepack,
            payload: envelope.payload.clone(),
            source_runtime_id: None,
            source_agent_id: None,
            source_role: None,
            tags: None,
        })
    }

    fn require_binding(&self, document_type: &str) -> Result<&CultNetDocumentBinding> {
        self.binding(document_type).ok_or_else(|| {
            anyhow!("No CultNet document binding is registered for {document_type:?}")
        })
    }
}

fn round_trip_typed<T>(value: &T) -> Result<T>
where
    T: Serialize + DeserializeOwned,
{
    Ok(rmp_serde::from_slice(&rmp_serde::to_vec(value)?)?)
}

fn now_utc_second() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
