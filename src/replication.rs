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
    pub schema_id: String,
    pub document_type: String,
    pub mutation_contract: Option<CultNetDocumentMutationContract>,
    pub payload_schema_version: Option<String>,
}

impl CultNetDocumentBinding {
    pub fn for_entry<T: DatabaseEntry>(payload_schema_version: impl Into<Option<String>>) -> Self {
        Self {
            document_type: T::TYPE.to_string(),
            schema_id: T::TYPE.to_string(),
            mutation_contract: None,
            payload_schema_version: payload_schema_version.into(),
        }
    }

    pub fn for_entry_with_schema_id<T: DatabaseEntry>(
        schema_id: impl Into<String>,
        payload_schema_version: impl Into<Option<String>>,
    ) -> Self {
        Self {
            document_type: T::TYPE.to_string(),
            schema_id: schema_id.into(),
            mutation_contract: None,
            payload_schema_version: payload_schema_version.into(),
        }
    }

    pub fn with_mutation_contract(mut self, contract: CultNetDocumentMutationContract) -> Self {
        self.mutation_contract = Some(contract);
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct CultNetDocumentRegistry {
    bindings_by_type: BTreeMap<String, CultNetDocumentBinding>,
    bindings_by_schema_id: BTreeMap<String, CultNetDocumentBinding>,
}

impl CultNetDocumentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, binding: CultNetDocumentBinding) -> &mut Self {
        self.bindings_by_schema_id
            .insert(binding.schema_id.clone(), binding.clone());
        self.bindings_by_type
            .insert(binding.document_type.clone(), binding);
        self
    }

    pub fn binding(&self, document_type: &str) -> Option<&CultNetDocumentBinding> {
        self.bindings_by_type.get(document_type)
    }

    pub fn binding_by_schema_id(&self, schema_id: &str) -> Option<&CultNetDocumentBinding> {
        self.bindings_by_schema_id.get(schema_id)
    }

    pub fn mutation_contracts(&self) -> Vec<CultNetDocumentMutationContract> {
        self.bindings_by_type
            .values()
            .filter_map(|binding| binding.mutation_contract.clone())
            .collect()
    }

    pub fn create_document_put_message<T>(
        &self,
        message_id: impl Into<String>,
        record_key: impl Into<String>,
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
                schema_id: binding.schema_id.clone(),
                record_key: record_key.into(),
                stored_at: options.stored_at.unwrap_or_else(now_utc_second),
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
        schema_id: impl Into<String>,
        record_key: impl Into<String>,
    ) -> CultNetMessage {
        CultNetMessage::DocumentDelete {
            message_id: message_id.into(),
            schema_id: schema_id.into(),
            record_key: record_key.into(),
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
        schema_ids: Option<&[String]>,
        record_keys: Option<&[String]>,
    ) -> Result<CultNetMessage> {
        let requested_schema_ids = schema_ids.map(|items| items.iter().collect::<BTreeSet<_>>());
        let requested_record_keys = record_keys.map(|items| items.iter().collect::<BTreeSet<_>>());
        let mut documents = Vec::new();
        for envelope in cache.snapshot() {
            let binding = self.require_binding(&envelope.r#type)?;
            if requested_schema_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&binding.schema_id))
            {
                continue;
            }
            if requested_record_keys
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
        schema_ids: Option<&[String]>,
        record_keys: Option<&[String]>,
    ) -> Result<CultNetMessage> {
        let requested_schema_ids = schema_ids.map(|items| items.iter().collect::<BTreeSet<_>>());
        let requested_record_keys = record_keys.map(|items| items.iter().collect::<BTreeSet<_>>());
        let mut documents = Vec::new();
        for envelope in cache.snapshot() {
            let binding = self.require_binding(&envelope.r#type)?;
            if requested_schema_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&binding.schema_id))
            {
                continue;
            }
            if requested_record_keys
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
        let binding = self.require_binding(T::TYPE)?;
        if document.schema_id != binding.schema_id {
            return Err(anyhow!(
                "schema id {:?} does not match registered Rust type {:?} schema {:?}",
                document.schema_id,
                T::TYPE,
                binding.schema_id
            ));
        }
        let value: T = serde_json::from_value(document.payload.clone()).with_context(|| {
            format!(
                "failed to decode CultNet payload schema {:?} as {}",
                binding.schema_id,
                T::SCHEMA_NAME
            )
        })?;
        cache.put(&document.record_key, &value)
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
            schema_id,
            record_key,
            ..
        } = message
        else {
            return Err(anyhow!("expected cultnet.document_delete.v0"));
        };
        let binding = self.require_binding(T::TYPE)?;
        if schema_id != &binding.schema_id {
            return Err(anyhow!(
                "schema id {:?} does not match registered Rust type {:?} schema {:?}",
                schema_id,
                T::TYPE,
                binding.schema_id
            ));
        }
        cache.delete::<T>(record_key)
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
        let binding = self.require_binding(T::TYPE)?;
        if document.schema_id != binding.schema_id {
            return Err(anyhow!(
                "schema id {:?} does not match registered Rust type {:?} schema {:?}",
                document.schema_id,
                T::TYPE,
                binding.schema_id
            ));
        }
        cache.put_envelope::<T>(CultCacheEnvelope {
            key: document.record_key.clone(),
            r#type: binding.document_type.clone(),
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
        let binding = self.require_binding(T::TYPE)?;
        for document in documents {
            if document.schema_id != binding.schema_id {
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
        let binding = self.require_binding(T::TYPE)?;
        for document in documents {
            if document.schema_id != binding.schema_id {
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
            schema_id: binding.schema_id.clone(),
            record_key: envelope.key.clone(),
            stored_at: envelope.stored_at.clone(),
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
            schema_id: binding.schema_id.clone(),
            record_key: envelope.key.clone(),
            stored_at: envelope.stored_at.clone(),
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
