use anyhow::{Result, anyhow};
use std::collections::{BTreeMap, BTreeSet};

use crate::{CultNetDocumentRegistry, CultNetMessage, CultNetRawDocumentRecord};

/// Read-only backing surface for a CultNet snapshot server.
///
/// Records returned here are already the stored wire records. The snapshot
/// server selects and clones them; it never decodes payloads, rewrites source
/// metadata, or applies them to another cache.
pub trait CultNetRawSnapshotSource {
    fn raw_snapshot(&self) -> Result<Vec<CultNetRawDocumentRecord>>;
}

impl CultNetRawSnapshotSource for Vec<CultNetRawDocumentRecord> {
    fn raw_snapshot(&self) -> Result<Vec<CultNetRawDocumentRecord>> {
        Ok(self.clone())
    }
}

impl<F> CultNetRawSnapshotSource for F
where
    F: Fn() -> Result<Vec<CultNetRawDocumentRecord>>,
{
    fn raw_snapshot(&self) -> Result<Vec<CultNetRawDocumentRecord>> {
        self()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CultNetReadOnlySnapshotPolicy {
    allowed_records: BTreeSet<(String, String)>,
}

impl CultNetReadOnlySnapshotPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(
        &mut self,
        schema_id: impl Into<String>,
        record_key: impl Into<String>,
    ) -> Result<&mut Self> {
        let schema_id = schema_id.into();
        let record_key = record_key.into();
        require_non_empty(&schema_id, "schema_id")?;
        require_non_empty(&record_key, "record_key")?;
        self.allowed_records.insert((schema_id, record_key));
        Ok(self)
    }

    fn allows(&self, schema_id: &str, record_key: &str) -> bool {
        self.allowed_records
            .contains(&(schema_id.to_string(), record_key.to_string()))
    }
}

/// Serve one raw snapshot request from an explicitly bounded, read-only view.
///
/// The document registry proves that every exposed schema belongs to the
/// runtime. The policy grants individual `(schema_id, record_key)` pairs. The
/// source owns the bytes and metadata; this function only selects records.
pub fn serve_read_only_raw_snapshot<S: CultNetRawSnapshotSource>(
    document_registry: &CultNetDocumentRegistry,
    policy: &CultNetReadOnlySnapshotPolicy,
    source: &S,
    request: &CultNetMessage,
) -> Result<CultNetMessage> {
    let CultNetMessage::SnapshotRequest {
        message_id,
        schema_ids,
        record_keys,
    } = request
    else {
        return Err(anyhow!("expected cultnet.snapshot_request.v0"));
    };
    require_non_empty(message_id, "message_id")?;
    reject_duplicates(schema_ids.as_deref(), "requested schema id")?;
    reject_duplicates(record_keys.as_deref(), "requested record key")?;

    let requested_schemas = schema_ids
        .as_ref()
        .map(|values| values.iter().map(String::as_str).collect::<BTreeSet<_>>());
    let requested_keys = record_keys
        .as_ref()
        .map(|values| values.iter().map(String::as_str).collect::<BTreeSet<_>>());
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();

    for document in source.raw_snapshot()? {
        let identity = (document.schema_id.clone(), document.record_key.clone());
        if !seen.insert(identity.clone()) {
            return Err(anyhow!(
                "snapshot source contains duplicate record {:?}/{:?}",
                identity.0,
                identity.1
            ));
        }
        if document_registry
            .binding_by_schema_id(&document.schema_id)
            .is_none()
        {
            return Err(anyhow!(
                "snapshot source record {:?}/{:?} uses an unregistered schema",
                document.schema_id,
                document.record_key
            ));
        }
        if !policy.allows(&document.schema_id, &document.record_key) {
            continue;
        }
        if requested_schemas
            .as_ref()
            .is_some_and(|schemas| !schemas.contains(document.schema_id.as_str()))
        {
            continue;
        }
        if requested_keys
            .as_ref()
            .is_some_and(|keys| !keys.contains(document.record_key.as_str()))
        {
            continue;
        }
        selected.push(document);
    }

    Ok(CultNetMessage::SnapshotResponseRaw {
        message_id: message_id.clone(),
        documents: selected,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CultNetSnapshotSourceExpectation {
    pub runtime_id: Option<String>,
    pub agent_id: Option<String>,
    pub role: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CultNetSnapshotRecordExpectation {
    pub schema_id: String,
    pub record_key: String,
    pub source: CultNetSnapshotSourceExpectation,
}

impl CultNetSnapshotRecordExpectation {
    pub fn new(schema_id: impl Into<String>, record_key: impl Into<String>) -> Self {
        Self {
            schema_id: schema_id.into(),
            record_key: record_key.into(),
            source: CultNetSnapshotSourceExpectation::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CultNetRawSnapshotQuery {
    message_id: String,
    expectations: BTreeMap<(String, String), CultNetSnapshotSourceExpectation>,
}

impl CultNetRawSnapshotQuery {
    pub fn new(
        message_id: impl Into<String>,
        records: Vec<CultNetSnapshotRecordExpectation>,
    ) -> Result<Self> {
        let message_id = message_id.into();
        require_non_empty(&message_id, "message_id")?;
        if records.is_empty() {
            return Err(anyhow!("snapshot query must request at least one record"));
        }
        let mut expectations = BTreeMap::new();
        for record in records {
            require_non_empty(&record.schema_id, "schema_id")?;
            require_non_empty(&record.record_key, "record_key")?;
            let identity = (record.schema_id, record.record_key);
            if expectations
                .insert(identity.clone(), record.source)
                .is_some()
            {
                return Err(anyhow!(
                    "snapshot query contains duplicate requested record {:?}/{:?}",
                    identity.0,
                    identity.1
                ));
            }
        }
        Ok(Self {
            message_id,
            expectations,
        })
    }

    pub fn request(&self) -> CultNetMessage {
        CultNetMessage::SnapshotRequest {
            message_id: self.message_id.clone(),
            schema_ids: Some(
                self.expectations
                    .keys()
                    .map(|(schema_id, _)| schema_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            ),
            record_keys: Some(
                self.expectations
                    .keys()
                    .map(|(_, record_key)| record_key.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            ),
        }
    }

    /// Validate a response and return records without mutating any local cache.
    pub fn accept_response(
        &self,
        response: CultNetMessage,
    ) -> Result<Vec<CultNetRawDocumentRecord>> {
        let CultNetMessage::SnapshotResponseRaw {
            message_id,
            documents,
        } = response
        else {
            return Err(anyhow!("expected cultnet.snapshot_response_raw.v0"));
        };
        if message_id != self.message_id {
            return Err(anyhow!(
                "snapshot response message id {:?} does not match request {:?}",
                message_id,
                self.message_id
            ));
        }

        let mut seen = BTreeSet::new();
        for document in &documents {
            let identity = (document.schema_id.clone(), document.record_key.clone());
            if !seen.insert(identity.clone()) {
                return Err(anyhow!(
                    "snapshot response contains duplicate record {:?}/{:?}",
                    identity.0,
                    identity.1
                ));
            }
            let expected = self.expectations.get(&identity).ok_or_else(|| {
                anyhow!(
                    "snapshot response contains unexpected record {:?}/{:?}",
                    identity.0,
                    identity.1
                )
            })?;
            require_expected_metadata(
                "source_runtime_id",
                expected.runtime_id.as_deref(),
                document.source_runtime_id.as_deref(),
                &identity,
            )?;
            require_expected_metadata(
                "source_agent_id",
                expected.agent_id.as_deref(),
                document.source_agent_id.as_deref(),
                &identity,
            )?;
            require_expected_metadata(
                "source_role",
                expected.role.as_deref(),
                document.source_role.as_deref(),
                &identity,
            )?;
            if let Some(expected_tags) = expected.tags.as_ref()
                && document.tags.as_ref() != Some(expected_tags)
            {
                return Err(anyhow!(
                    "snapshot response record {:?}/{:?} has unexpected tags: expected {:?}, got {:?}",
                    identity.0,
                    identity.1,
                    expected_tags,
                    document.tags
                ));
            }
        }
        Ok(documents)
    }
}

pub fn query_read_only_raw_snapshot<F>(
    query: &CultNetRawSnapshotQuery,
    exchange: F,
) -> Result<Vec<CultNetRawDocumentRecord>>
where
    F: FnOnce(CultNetMessage) -> Result<CultNetMessage>,
{
    query.accept_response(exchange(query.request())?)
}

fn require_expected_metadata(
    field: &str,
    expected: Option<&str>,
    actual: Option<&str>,
    identity: &(String, String),
) -> Result<()> {
    if let Some(expected) = expected
        && actual != Some(expected)
    {
        return Err(anyhow!(
            "snapshot response record {:?}/{:?} has unexpected {field}: expected {:?}, got {:?}",
            identity.0,
            identity.1,
            expected,
            actual
        ));
    }
    Ok(())
}

fn reject_duplicates(values: Option<&[String]>, label: &str) -> Result<()> {
    let Some(values) = values else {
        return Ok(());
    };
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(anyhow!("duplicate {label} {value:?}"));
        }
    }
    Ok(())
}

fn require_non_empty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{field} must be non-empty"));
    }
    Ok(())
}
