use anyhow::Result;
use anyhow::anyhow;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::CultNetMessage;
use crate::CultNetSchemaDescriptor;
use crate::CultNetSchemaKind;
use crate::CultNetWireContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CultNetSchemaRegistration {
    pub schema_id: String,
    pub kind: CultNetSchemaKind,
    pub wire_contracts: Vec<CultNetWireContract>,
    pub schema_version: Option<String>,
    pub document_type: Option<String>,
    pub title: Option<String>,
    pub schema_json: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CultNetSchemaCatalogOptions {
    pub include_schema_json: bool,
    pub schema_ids: Option<Vec<String>>,
    pub kinds: Option<Vec<CultNetSchemaKind>>,
}

#[derive(Clone, Debug, Default)]
pub struct CultNetSchemaRegistry {
    entries: BTreeMap<String, CultNetSchemaDescriptor>,
}

impl CultNetSchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, registration: CultNetSchemaRegistration) -> Result<()> {
        if registration.schema_id.trim().is_empty() {
            return Err(anyhow!("schema_id must be non-empty"));
        }
        if registration.wire_contracts.is_empty() {
            return Err(anyhow!("wire_contracts must contain at least one entry"));
        }

        let content_hash = if let Some(schema_json) = registration.schema_json.as_deref() {
            canonical_schema_hash(schema_json)?
        } else {
            return Err(anyhow!(
                "schema_json is required so discovery can advertise canonical hashes"
            ));
        };

        self.entries.insert(
            registration.schema_id.clone(),
            CultNetSchemaDescriptor {
                schema_id: registration.schema_id,
                kind: registration.kind,
                schema_version: registration.schema_version,
                document_type: registration.document_type,
                title: registration.title,
                wire_contracts: registration.wire_contracts,
                content_hash,
                schema_json: registration.schema_json,
            },
        );

        Ok(())
    }

    pub fn get(
        &self,
        schema_id: &str,
        include_schema_json: bool,
    ) -> Option<CultNetSchemaDescriptor> {
        self.entries
            .get(schema_id)
            .map(|entry| sanitize_descriptor(entry, include_schema_json))
    }

    pub fn list(&self, options: &CultNetSchemaCatalogOptions) -> Vec<CultNetSchemaDescriptor> {
        let requested_ids = options
            .schema_ids
            .as_ref()
            .map(|values| values.iter().cloned().collect::<BTreeSet<_>>());
        let requested_kinds = options
            .kinds
            .as_ref()
            .map(|values| values.iter().copied().collect::<BTreeSet<_>>());

        self.entries
            .values()
            .filter(|entry| {
                if let Some(requested_ids) = &requested_ids
                    && !requested_ids.contains(&entry.schema_id)
                {
                    return false;
                }

                if let Some(requested_kinds) = &requested_kinds
                    && !requested_kinds.contains(&entry.kind)
                {
                    return false;
                }

                true
            })
            .map(|entry| sanitize_descriptor(entry, options.include_schema_json))
            .collect()
    }

    pub fn create_catalog_response(&self, request: &CultNetMessage) -> Result<CultNetMessage> {
        let CultNetMessage::SchemaCatalogRequest {
            message_id,
            include_schema_json,
            schema_ids,
            kinds,
        } = request
        else {
            return Err(anyhow!(
                "expected cultnet.schema_catalog_request.v0 for schema discovery"
            ));
        };

        Ok(CultNetMessage::SchemaCatalogResponse {
            message_id: message_id.clone(),
            schemas: self.list(&CultNetSchemaCatalogOptions {
                include_schema_json: include_schema_json.unwrap_or(false),
                schema_ids: schema_ids.clone(),
                kinds: kinds.clone(),
            }),
        })
    }
}

fn sanitize_descriptor(
    descriptor: &CultNetSchemaDescriptor,
    include_schema_json: bool,
) -> CultNetSchemaDescriptor {
    let mut clone = descriptor.clone();
    if !include_schema_json {
        clone.schema_json = None;
    }
    clone
}

fn canonical_schema_hash(schema_json: &str) -> Result<String> {
    let value: Value = serde_json::from_str(schema_json)?;
    let canonical = stable_stringify(&value);
    Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
}

fn stable_stringify(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("string serialization"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(stable_stringify)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key).expect("key serialization"),
                            stable_stringify(value)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

pub fn builtin_schema_registry() -> Result<CultNetSchemaRegistry> {
    let mut registry = CultNetSchemaRegistry::new();

    for registration in [
        schema_registration(
            include_str!("../contracts/cultnet.hello.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("cultnet.hello.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.document-mutation-contract.schema.json"),
            CultNetSchemaKind::SharedContract,
            vec![CultNetWireContract::CultNetSchemaV0],
            None,
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.login.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.login.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.register.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.register.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.verify.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.verify.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.login-success.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.login_success.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.error.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.error.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.sample-change-name.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.sample.change_name.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.sample-chat.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.sample.chat.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.document-put.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("cultnet.document_put.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.document-delete.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("cultnet.document_delete.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.raw-document-record.schema.json"),
            CultNetSchemaKind::SharedContract,
            vec![CultNetWireContract::CultNetSchemaV0],
            None,
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.document-put-raw.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("cultnet.document_put_raw.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.snapshot-request.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("cultnet.snapshot_request.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.snapshot-response.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("cultnet.snapshot_response.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.snapshot-response-raw.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("cultnet.snapshot_response_raw.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.schema-catalog-request.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.schema_catalog_request.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/cultnet.schema-catalog-response.schema.json"),
            CultNetSchemaKind::WireMessage,
            vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            Some("cultnet.schema_catalog_response.v0"),
            None,
        )?,
        schema_registration(
            include_str!("../contracts/ghostlight.agent-state.schema.json"),
            CultNetSchemaKind::DocumentPayload,
            vec![CultNetWireContract::CultNetSchemaV0],
            Some("ghostlight.agent_state.v0"),
            Some("ghostlight.agent-state"),
        )?,
    ] {
        registry.register(registration)?;
    }

    Ok(registry)
}

fn schema_registration(
    schema_json: &str,
    kind: CultNetSchemaKind,
    wire_contracts: Vec<CultNetWireContract>,
    schema_version: Option<&str>,
    document_type: Option<&str>,
) -> Result<CultNetSchemaRegistration> {
    let value: Value = serde_json::from_str(schema_json)?;
    let schema_id = value
        .get("$id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("schema is missing $id"))?;
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .map(str::to_string);

    Ok(CultNetSchemaRegistration {
        schema_id: schema_id.to_string(),
        kind,
        wire_contracts,
        schema_version: schema_version.map(str::to_string),
        document_type: document_type.map(str::to_string),
        title,
        schema_json: Some(schema_json.to_string()),
    })
}
