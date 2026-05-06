use anyhow::Result;
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CultNetWireContract {
    #[serde(rename = "cultnet.schema.v0")]
    CultNetSchemaV0,
    #[serde(rename = "gamecult.networking.v0")]
    GameCultNetworkingV0,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CultNetSchemaKind {
    WireMessage,
    DocumentPayload,
    SharedContract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CultNetRawPayloadEncoding {
    Messagepack,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CultNetDocumentRecord<TPayload = Value> {
    pub document_type: String,
    pub document_key: String,
    pub stored_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_schema_version: Option<String>,
    pub payload: TPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CultNetRawDocumentRecord {
    pub document_type: String,
    pub document_key: String,
    pub stored_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_schema_version: Option<String>,
    pub payload_encoding: CultNetRawPayloadEncoding,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CultNetSchemaDescriptor {
    pub schema_id: String,
    pub kind: CultNetSchemaKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub wire_contracts: Vec<CultNetWireContract>,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_json: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "schemaVersion")]
pub enum CultNetMessage {
    #[serde(rename = "cultnet.hello.v0", rename_all = "camelCase")]
    Hello {
        runtime_id: String,
        runtime_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        supported_document_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        supported_message_versions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        supports_schema_catalog: Option<bool>,
    },
    #[serde(rename = "cultnet.login.v0", rename_all = "camelCase")]
    Login {
        nonce: String,
        auth: String,
        password: String,
    },
    #[serde(rename = "cultnet.register.v0", rename_all = "camelCase")]
    Register {
        nonce: String,
        email: String,
        password: String,
        name: String,
    },
    #[serde(rename = "cultnet.verify.v0", rename_all = "camelCase")]
    Verify { nonce: String, session: String },
    #[serde(rename = "cultnet.login_success.v0", rename_all = "camelCase")]
    LoginSuccess { nonce: String, session: String },
    #[serde(rename = "cultnet.error.v0", rename_all = "camelCase")]
    Error { error: String },
    #[serde(rename = "cultnet.sample.change_name.v0", rename_all = "camelCase")]
    SampleChangeName { name: String },
    #[serde(rename = "cultnet.sample.chat.v0", rename_all = "camelCase")]
    SampleChat { text: String },
    #[serde(rename = "cultnet.document_put.v0", rename_all = "camelCase")]
    DocumentPut {
        message_id: String,
        document: CultNetDocumentRecord<Value>,
    },
    #[serde(rename = "cultnet.document_delete.v0", rename_all = "camelCase")]
    DocumentDelete {
        message_id: String,
        document_type: String,
        document_key: String,
    },
    #[serde(rename = "cultnet.document_put_raw.v0", rename_all = "camelCase")]
    DocumentPutRaw {
        message_id: String,
        document: CultNetRawDocumentRecord,
    },
    #[serde(rename = "cultnet.snapshot_request.v0", rename_all = "camelCase")]
    SnapshotRequest {
        message_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        document_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        document_keys: Option<Vec<String>>,
    },
    #[serde(rename = "cultnet.snapshot_response.v0", rename_all = "camelCase")]
    SnapshotResponse {
        message_id: String,
        documents: Vec<CultNetDocumentRecord<Value>>,
    },
    #[serde(rename = "cultnet.snapshot_response_raw.v0", rename_all = "camelCase")]
    SnapshotResponseRaw {
        message_id: String,
        documents: Vec<CultNetRawDocumentRecord>,
    },
    #[serde(rename = "cultnet.schema_catalog_request.v0", rename_all = "camelCase")]
    SchemaCatalogRequest {
        message_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        include_schema_json: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kinds: Option<Vec<CultNetSchemaKind>>,
    },
    #[serde(
        rename = "cultnet.schema_catalog_response.v0",
        rename_all = "camelCase"
    )]
    SchemaCatalogResponse {
        message_id: String,
        schemas: Vec<CultNetSchemaDescriptor>,
    },
}

pub fn parse_cultnet_message(
    wire_value: &rmpv::Value,
    contract: CultNetWireContract,
) -> Result<CultNetMessage> {
    match contract {
        CultNetWireContract::CultNetSchemaV0 => {
            let message = match schema_version_from_wire_value(wire_value)? {
                Some("cultnet.document_put_raw.v0" | "cultnet.snapshot_response_raw.v0") => {
                    parse_raw_cultnet_schema_message(wire_value)?
                }
                _ => {
                    let json_value: Value = rmp_serde::from_slice(&rmp_serde::to_vec(wire_value)?)?;
                    serde_json::from_value(json_value)?
                }
            };
            validate_message(&message)?;
            Ok(message)
        }
        CultNetWireContract::GameCultNetworkingV0 => parse_gamecult_networking_message(wire_value),
    }
}

pub fn encode_cultnet_message_for_wire(
    message: &CultNetMessage,
    contract: CultNetWireContract,
) -> Result<rmpv::Value> {
    validate_message(message)?;
    match contract {
        CultNetWireContract::CultNetSchemaV0 => match message {
            CultNetMessage::DocumentPutRaw { .. } | CultNetMessage::SnapshotResponseRaw { .. } => {
                encode_raw_cultnet_schema_message(message)
            }
            _ => Ok(rmp_serde::from_slice(&rmp_serde::to_vec(
                &serde_json::to_value(message)?,
            )?)?),
        },
        CultNetWireContract::GameCultNetworkingV0 => encode_gamecult_networking_message(message),
    }
}

pub fn encode_cultnet_message_to_vec(
    message: &CultNetMessage,
    contract: CultNetWireContract,
) -> Result<Vec<u8>> {
    let wire_value = encode_cultnet_message_for_wire(message, contract)?;
    Ok(rmp_serde::to_vec(&wire_value)?)
}

pub fn decode_cultnet_message_from_slice(
    bytes: &[u8],
    contract: CultNetWireContract,
) -> Result<CultNetMessage> {
    if contract == CultNetWireContract::CultNetSchemaV0 {
        let wire_value: rmpv::Value = rmp_serde::from_slice(bytes)?;
        return parse_cultnet_message(&wire_value, contract);
    }
    let wire_value: rmpv::Value = rmp_serde::from_slice(bytes)?;
    parse_cultnet_message(&wire_value, contract)
}

fn validate_message(message: &CultNetMessage) -> Result<()> {
    match message {
        CultNetMessage::Hello {
            runtime_id,
            runtime_kind,
            agent_id,
            role,
            display_name,
            supported_document_types,
            supported_message_versions,
            supports_schema_catalog: _,
        } => {
            require_non_empty(runtime_id, "runtimeId")?;
            require_non_empty(runtime_kind, "runtimeKind")?;
            require_optional_non_empty(agent_id.as_deref(), "agentId")?;
            require_optional_non_empty(role.as_deref(), "role")?;
            require_optional_non_empty(display_name.as_deref(), "displayName")?;
            require_optional_string_vec(
                supported_document_types.as_deref(),
                "supportedDocumentTypes",
            )?;
            require_optional_string_vec(
                supported_message_versions.as_deref(),
                "supportedMessageVersions",
            )?;
        }
        CultNetMessage::Login {
            nonce,
            auth,
            password,
        } => {
            require_non_empty(nonce, "nonce")?;
            require_non_empty(auth, "auth")?;
            require_non_empty(password, "password")?;
        }
        CultNetMessage::Register {
            nonce,
            email,
            password,
            name,
        } => {
            require_non_empty(nonce, "nonce")?;
            require_non_empty(email, "email")?;
            require_non_empty(password, "password")?;
            require_non_empty(name, "name")?;
        }
        CultNetMessage::Verify { nonce, session }
        | CultNetMessage::LoginSuccess { nonce, session } => {
            require_non_empty(nonce, "nonce")?;
            require_non_empty(session, "session")?;
        }
        CultNetMessage::Error { error } => require_non_empty(error, "error")?,
        CultNetMessage::SampleChangeName { name } => require_non_empty(name, "name")?,
        CultNetMessage::SampleChat { text } => require_non_empty(text, "text")?,
        CultNetMessage::DocumentPut {
            message_id,
            document,
        } => {
            require_non_empty(message_id, "messageId")?;
            validate_document_record(document)?;
        }
        CultNetMessage::DocumentDelete {
            message_id,
            document_type,
            document_key,
        } => {
            require_non_empty(message_id, "messageId")?;
            require_non_empty(document_type, "documentType")?;
            require_non_empty(document_key, "documentKey")?;
        }
        CultNetMessage::DocumentPutRaw {
            message_id,
            document,
        } => {
            require_non_empty(message_id, "messageId")?;
            validate_raw_document_record(document)?;
        }
        CultNetMessage::SnapshotRequest {
            message_id,
            document_types,
            document_keys,
        } => {
            require_non_empty(message_id, "messageId")?;
            require_optional_string_vec(document_types.as_deref(), "documentTypes")?;
            require_optional_string_vec(document_keys.as_deref(), "documentKeys")?;
        }
        CultNetMessage::SnapshotResponse {
            message_id,
            documents,
        } => {
            require_non_empty(message_id, "messageId")?;
            for document in documents {
                validate_document_record(document)?;
            }
        }
        CultNetMessage::SnapshotResponseRaw {
            message_id,
            documents,
        } => {
            require_non_empty(message_id, "messageId")?;
            for document in documents {
                validate_raw_document_record(document)?;
            }
        }
        CultNetMessage::SchemaCatalogRequest {
            message_id,
            include_schema_json: _,
            schema_ids,
            kinds: _,
        } => {
            require_non_empty(message_id, "messageId")?;
            require_optional_string_vec(schema_ids.as_deref(), "schemaIds")?;
        }
        CultNetMessage::SchemaCatalogResponse {
            message_id,
            schemas,
        } => {
            require_non_empty(message_id, "messageId")?;
            for schema in schemas {
                validate_schema_descriptor(schema)?;
            }
        }
    }
    Ok(())
}

fn validate_document_record(document: &CultNetDocumentRecord<Value>) -> Result<()> {
    require_non_empty(&document.document_type, "documentType")?;
    require_non_empty(&document.document_key, "documentKey")?;
    require_non_empty(&document.stored_at, "storedAt")?;
    require_optional_non_empty(
        document.payload_schema_version.as_deref(),
        "payloadSchemaVersion",
    )?;
    require_optional_non_empty(document.source_runtime_id.as_deref(), "sourceRuntimeId")?;
    require_optional_non_empty(document.source_agent_id.as_deref(), "sourceAgentId")?;
    require_optional_non_empty(document.source_role.as_deref(), "sourceRole")?;
    require_optional_string_vec(document.tags.as_deref(), "tags")?;
    Ok(())
}

fn validate_raw_document_record(document: &CultNetRawDocumentRecord) -> Result<()> {
    require_non_empty(&document.document_type, "documentType")?;
    require_non_empty(&document.document_key, "documentKey")?;
    require_non_empty(&document.stored_at, "storedAt")?;
    require_optional_non_empty(
        document.payload_schema_version.as_deref(),
        "payloadSchemaVersion",
    )?;
    if document.payload.is_empty() {
        return Err(anyhow!(
            "CultNet field payload must contain non-empty MessagePack bytes"
        ));
    }
    require_optional_non_empty(document.source_runtime_id.as_deref(), "sourceRuntimeId")?;
    require_optional_non_empty(document.source_agent_id.as_deref(), "sourceAgentId")?;
    require_optional_non_empty(document.source_role.as_deref(), "sourceRole")?;
    require_optional_string_vec(document.tags.as_deref(), "tags")?;
    Ok(())
}

fn validate_schema_descriptor(schema: &CultNetSchemaDescriptor) -> Result<()> {
    require_non_empty(&schema.schema_id, "schemaId")?;
    require_optional_non_empty(schema.schema_version.as_deref(), "schemaVersion")?;
    require_optional_non_empty(schema.document_type.as_deref(), "documentType")?;
    require_optional_non_empty(schema.title.as_deref(), "title")?;
    require_non_empty(&schema.content_hash, "contentHash")?;
    require_optional_non_empty(schema.schema_json.as_deref(), "schemaJson")?;

    if schema.wire_contracts.is_empty() {
        return Err(anyhow!(
            "CultNet field wireContracts must contain at least one supported contract"
        ));
    }

    Ok(())
}

fn require_non_empty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("CultNet field {field} must be non-empty"));
    }
    Ok(())
}

fn require_optional_non_empty(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(value) = value {
        require_non_empty(value, field)?;
    }
    Ok(())
}

fn require_optional_string_vec(value: Option<&[String]>, field: &str) -> Result<()> {
    if let Some(values) = value {
        for item in values {
            require_non_empty(item, field)?;
        }
    }
    Ok(())
}

fn schema_version_from_wire_value(input: &rmpv::Value) -> Result<Option<&str>> {
    let Some(object) = input.as_map() else {
        return Ok(None);
    };

    Ok(object.iter().find_map(|(key, value)| {
        key.as_str()
            .filter(|candidate| *candidate == "schemaVersion")
            .and_then(|_| value.as_str())
    }))
}

fn parse_raw_cultnet_schema_message(input: &rmpv::Value) -> Result<CultNetMessage> {
    let object = input
        .as_map()
        .ok_or_else(|| anyhow!("cultnet.schema.v0 raw messages must be objects"))?;

    let get = |name: &str| -> Option<&rmpv::Value> {
        object.iter().find_map(|(key, value)| {
            key.as_str()
                .filter(|candidate| *candidate == name)
                .map(|_| value)
        })
    };

    let schema_version = require_legacy_string(get("schemaVersion"), "schemaVersion")?;
    match schema_version.as_str() {
        "cultnet.document_put_raw.v0" => Ok(CultNetMessage::DocumentPutRaw {
            message_id: require_legacy_string(get("messageId"), "messageId")?,
            document: require_raw_document_record(get("document"), "document")?,
        }),
        "cultnet.snapshot_response_raw.v0" => {
            let documents = get("documents")
                .and_then(rmpv::Value::as_array)
                .ok_or_else(|| anyhow!("documents must be an array"))?
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    require_raw_document_record(value.into(), &format!("documents[{index}]"))
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(CultNetMessage::SnapshotResponseRaw {
                message_id: require_legacy_string(get("messageId"), "messageId")?,
                documents,
            })
        }
        _ => Err(anyhow!(
            "Unsupported raw cultnet.schema.v0 schemaVersion {schema_version}"
        )),
    }
}

fn encode_raw_cultnet_schema_message(message: &CultNetMessage) -> Result<rmpv::Value> {
    Ok(rmpv::Value::Map(match message {
        CultNetMessage::DocumentPutRaw {
            message_id,
            document,
        } => vec![
            (
                rmpv::Value::from("schemaVersion"),
                rmpv::Value::from("cultnet.document_put_raw.v0"),
            ),
            (
                rmpv::Value::from("messageId"),
                rmpv::Value::from(message_id.as_str()),
            ),
            (
                rmpv::Value::from("document"),
                encode_raw_document_record(document),
            ),
        ],
        CultNetMessage::SnapshotResponseRaw {
            message_id,
            documents,
        } => vec![
            (
                rmpv::Value::from("schemaVersion"),
                rmpv::Value::from("cultnet.snapshot_response_raw.v0"),
            ),
            (
                rmpv::Value::from("messageId"),
                rmpv::Value::from(message_id.as_str()),
            ),
            (
                rmpv::Value::from("documents"),
                rmpv::Value::Array(documents.iter().map(encode_raw_document_record).collect()),
            ),
        ],
        _ => {
            return Err(anyhow!(
                "Message is not a raw cultnet.schema.v0 binary replication message"
            ));
        }
    }))
}

fn require_raw_document_record(
    value: Option<&rmpv::Value>,
    field_name: &str,
) -> Result<CultNetRawDocumentRecord> {
    let object = value
        .and_then(rmpv::Value::as_map)
        .ok_or_else(|| anyhow!("{field_name} must be an object"))?;

    let get = |name: &str| -> Option<&rmpv::Value> {
        object.iter().find_map(|(key, value)| {
            key.as_str()
                .filter(|candidate| *candidate == name)
                .map(|_| value)
        })
    };

    let payload_encoding = require_legacy_string(
        get("payloadEncoding"),
        &format!("{field_name}.payloadEncoding"),
    )?;

    Ok(CultNetRawDocumentRecord {
        document_type: require_legacy_string(
            get("documentType"),
            &format!("{field_name}.documentType"),
        )?,
        document_key: require_legacy_string(
            get("documentKey"),
            &format!("{field_name}.documentKey"),
        )?,
        stored_at: require_legacy_string(get("storedAt"), &format!("{field_name}.storedAt"))?,
        payload_schema_version: require_legacy_optional_string(
            get("payloadSchemaVersion"),
            &format!("{field_name}.payloadSchemaVersion"),
        )?,
        payload_encoding: match payload_encoding.as_str() {
            "messagepack" => CultNetRawPayloadEncoding::Messagepack,
            _ => {
                return Err(anyhow!(
                    "{field_name}.payloadEncoding has unsupported value {payload_encoding}"
                ));
            }
        },
        payload: get("payload")
            .and_then(rmpv::Value::as_slice)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| anyhow!("{field_name}.payload must be binary MessagePack bytes"))?,
        source_runtime_id: require_legacy_optional_string(
            get("sourceRuntimeId"),
            &format!("{field_name}.sourceRuntimeId"),
        )?,
        source_agent_id: require_legacy_optional_string(
            get("sourceAgentId"),
            &format!("{field_name}.sourceAgentId"),
        )?,
        source_role: require_legacy_optional_string(
            get("sourceRole"),
            &format!("{field_name}.sourceRole"),
        )?,
        tags: require_legacy_optional_string_array(get("tags"), &format!("{field_name}.tags"))?,
    })
}

fn encode_raw_document_record(document: &CultNetRawDocumentRecord) -> rmpv::Value {
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("documentType"),
            rmpv::Value::from(document.document_type.as_str()),
        ),
        (
            rmpv::Value::from("documentKey"),
            rmpv::Value::from(document.document_key.as_str()),
        ),
        (
            rmpv::Value::from("storedAt"),
            rmpv::Value::from(document.stored_at.as_str()),
        ),
        (
            rmpv::Value::from("payloadSchemaVersion"),
            document
                .payload_schema_version
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
        (
            rmpv::Value::from("payloadEncoding"),
            rmpv::Value::from(match document.payload_encoding {
                CultNetRawPayloadEncoding::Messagepack => "messagepack",
            }),
        ),
        (
            rmpv::Value::from("payload"),
            rmpv::Value::Binary(document.payload.clone()),
        ),
        (
            rmpv::Value::from("sourceRuntimeId"),
            document
                .source_runtime_id
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
        (
            rmpv::Value::from("sourceAgentId"),
            document
                .source_agent_id
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
        (
            rmpv::Value::from("sourceRole"),
            document
                .source_role
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
        (
            rmpv::Value::from("tags"),
            legacy_optional_string_array(document.tags.as_deref()),
        ),
    ])
}

fn parse_gamecult_networking_message(input: &rmpv::Value) -> Result<CultNetMessage> {
    let items = input.as_array().ok_or_else(|| {
        anyhow!("gamecult.networking.v0 messages must be a 2-element union array")
    })?;
    if items.len() != 2 {
        return Err(anyhow!(
            "gamecult.networking.v0 messages must be a 2-element union array"
        ));
    }
    let tag = items[0]
        .as_i64()
        .ok_or_else(|| anyhow!("gamecult.networking.v0 message tag must be an integer"))?;
    let payload = items[1]
        .as_array()
        .ok_or_else(|| anyhow!("gamecult.networking.v0 message payload must be an array"))?;
    match tag {
        0 => Ok(CultNetMessage::Login {
            nonce: require_legacy_bytes(payload.first(), "LoginMessage.Nonce")?,
            auth: require_legacy_bytes(payload.get(1), "LoginMessage.Auth")?,
            password: require_legacy_bytes(payload.get(2), "LoginMessage.Password")?,
        }),
        1 => Ok(CultNetMessage::Register {
            nonce: require_legacy_bytes(payload.first(), "RegisterMessage.Nonce")?,
            email: require_legacy_bytes(payload.get(1), "RegisterMessage.Email")?,
            password: require_legacy_bytes(payload.get(2), "RegisterMessage.Password")?,
            name: require_legacy_bytes(payload.get(3), "RegisterMessage.Name")?,
        }),
        2 => Ok(CultNetMessage::Verify {
            nonce: require_legacy_bytes(payload.first(), "VerifyMessage.Nonce")?,
            session: require_legacy_bytes(payload.get(1), "VerifyMessage.Session")?,
        }),
        3 => Ok(CultNetMessage::LoginSuccess {
            nonce: require_legacy_bytes(payload.first(), "LoginSuccessMessage.Nonce")?,
            session: require_legacy_bytes(payload.get(1), "LoginSuccessMessage.Session")?,
        }),
        4 => Ok(CultNetMessage::Error {
            error: require_legacy_string(payload.first(), "ErrorMessage.Error")?,
        }),
        5 => Ok(CultNetMessage::SampleChangeName {
            name: require_legacy_string(payload.first(), "ChangeNameMessage.Name")?,
        }),
        6 => Ok(CultNetMessage::SampleChat {
            text: require_legacy_string(payload.first(), "ChatMessage.Text")?,
        }),
        7 => Ok(CultNetMessage::SchemaCatalogRequest {
            message_id: require_legacy_string(
                payload.first(),
                "SchemaCatalogRequestMessage.MessageId",
            )?,
            include_schema_json: Some(require_legacy_bool(
                payload.get(1),
                "SchemaCatalogRequestMessage.IncludeSchemaJson",
            )?),
            schema_ids: require_legacy_optional_string_array(
                payload.get(2),
                "SchemaCatalogRequestMessage.SchemaIds",
            )?,
            kinds: require_legacy_optional_schema_kind_array(
                payload.get(3),
                "SchemaCatalogRequestMessage.Kinds",
            )?,
        }),
        8 => Ok(CultNetMessage::SchemaCatalogResponse {
            message_id: require_legacy_string(
                payload.first(),
                "SchemaCatalogResponseMessage.MessageId",
            )?,
            schemas: require_legacy_schema_descriptor_array(
                payload.get(1),
                "SchemaCatalogResponseMessage.Schemas",
            )?,
        }),
        _ => Err(anyhow!(
            "Unsupported gamecult.networking.v0 union tag {tag}"
        )),
    }
}

fn encode_gamecult_networking_message(message: &CultNetMessage) -> Result<rmpv::Value> {
    let pair = match message {
        CultNetMessage::Login {
            nonce,
            auth,
            password,
        } => vec![
            rmpv::Value::from(0),
            rmpv::Value::Array(vec![
                legacy_bytes(nonce, "LoginMessage.Nonce")?,
                legacy_bytes(auth, "LoginMessage.Auth")?,
                legacy_bytes(password, "LoginMessage.Password")?,
            ]),
        ],
        CultNetMessage::Register {
            nonce,
            email,
            password,
            name,
        } => vec![
            rmpv::Value::from(1),
            rmpv::Value::Array(vec![
                legacy_bytes(nonce, "RegisterMessage.Nonce")?,
                legacy_bytes(email, "RegisterMessage.Email")?,
                legacy_bytes(password, "RegisterMessage.Password")?,
                legacy_bytes(name, "RegisterMessage.Name")?,
            ]),
        ],
        CultNetMessage::Verify { nonce, session } => vec![
            rmpv::Value::from(2),
            rmpv::Value::Array(vec![
                legacy_bytes(nonce, "VerifyMessage.Nonce")?,
                legacy_bytes(session, "VerifyMessage.Session")?,
            ]),
        ],
        CultNetMessage::LoginSuccess { nonce, session } => vec![
            rmpv::Value::from(3),
            rmpv::Value::Array(vec![
                legacy_bytes(nonce, "LoginSuccessMessage.Nonce")?,
                legacy_bytes(session, "LoginSuccessMessage.Session")?,
            ]),
        ],
        CultNetMessage::Error { error } => {
            vec![
                rmpv::Value::from(4),
                rmpv::Value::Array(vec![error.as_str().into()]),
            ]
        }
        CultNetMessage::SampleChangeName { name } => {
            vec![
                rmpv::Value::from(5),
                rmpv::Value::Array(vec![name.as_str().into()]),
            ]
        }
        CultNetMessage::SampleChat { text } => {
            vec![
                rmpv::Value::from(6),
                rmpv::Value::Array(vec![text.as_str().into()]),
            ]
        }
        CultNetMessage::SchemaCatalogRequest {
            message_id,
            include_schema_json,
            schema_ids,
            kinds,
        } => vec![
            rmpv::Value::from(7),
            rmpv::Value::Array(vec![
                message_id.as_str().into(),
                rmpv::Value::from(include_schema_json.unwrap_or(false)),
                legacy_optional_string_array(schema_ids.as_deref()),
                legacy_optional_schema_kind_array(kinds.as_deref()),
            ]),
        ],
        CultNetMessage::SchemaCatalogResponse {
            message_id,
            schemas,
        } => vec![
            rmpv::Value::from(8),
            rmpv::Value::Array(vec![
                message_id.as_str().into(),
                rmpv::Value::Array(
                    schemas
                        .iter()
                        .map(legacy_schema_descriptor)
                        .collect::<Result<Vec<_>>>()?,
                ),
            ]),
        ],
        _ => {
            return Err(anyhow!(
                "Message is not defined in the gamecult.networking.v0 contract"
            ));
        }
    };
    Ok(rmpv::Value::Array(pair))
}

fn require_legacy_bytes(value: Option<&rmpv::Value>, field_name: &str) -> Result<String> {
    let bytes = value
        .and_then(rmpv::Value::as_slice)
        .ok_or_else(|| anyhow!("{field_name} must be binary data in gamecult.networking.v0"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn require_legacy_string(value: Option<&rmpv::Value>, field_name: &str) -> Result<String> {
    let value = value
        .and_then(rmpv::Value::as_str)
        .ok_or_else(|| anyhow!("{field_name} must be a string in gamecult.networking.v0"))?;
    Ok(value.to_string())
}

fn require_legacy_bool(value: Option<&rmpv::Value>, field_name: &str) -> Result<bool> {
    value
        .and_then(rmpv::Value::as_bool)
        .ok_or_else(|| anyhow!("{field_name} must be a boolean in gamecult.networking.v0"))
}

fn require_legacy_optional_string_array(
    value: Option<&rmpv::Value>,
    field_name: &str,
) -> Result<Option<Vec<String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_nil() {
        return Ok(None);
    }
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("{field_name} must be an array in gamecult.networking.v0"))?;
    let values = items
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| anyhow!("{field_name} must contain only strings"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(values))
}

fn require_legacy_optional_schema_kind_array(
    value: Option<&rmpv::Value>,
    field_name: &str,
) -> Result<Option<Vec<CultNetSchemaKind>>> {
    let Some(values) = require_legacy_optional_string_array(value, field_name)? else {
        return Ok(None);
    };
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "wire_message" => Ok(CultNetSchemaKind::WireMessage),
            "document_payload" => Ok(CultNetSchemaKind::DocumentPayload),
            "shared_contract" => Ok(CultNetSchemaKind::SharedContract),
            _ => Err(anyhow!("{field_name} has unsupported schema kind {value}")),
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn require_legacy_schema_descriptor_array(
    value: Option<&rmpv::Value>,
    field_name: &str,
) -> Result<Vec<CultNetSchemaDescriptor>> {
    let items = value
        .and_then(rmpv::Value::as_array)
        .ok_or_else(|| anyhow!("{field_name} must be an array in gamecult.networking.v0"))?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            require_legacy_schema_descriptor(item, &format!("{field_name}[{index}]"))
        })
        .collect()
}

fn require_legacy_schema_descriptor(
    value: &rmpv::Value,
    field_name: &str,
) -> Result<CultNetSchemaDescriptor> {
    let object = value
        .as_map()
        .ok_or_else(|| anyhow!("{field_name} must be an object in gamecult.networking.v0"))?;

    let get = |name: &str| -> Option<&rmpv::Value> {
        object.iter().find_map(|(key, value)| {
            key.as_str()
                .filter(|candidate| *candidate == name)
                .map(|_| value)
        })
    };

    let schema_id = require_legacy_string(get("schemaId"), &format!("{field_name}.SchemaId"))?;
    let kind = require_legacy_string(get("kind"), &format!("{field_name}.Kind"))?;
    let schema_version = require_legacy_optional_string(
        get("schemaVersion"),
        &format!("{field_name}.SchemaVersion"),
    )?;
    let document_type =
        require_legacy_optional_string(get("documentType"), &format!("{field_name}.DocumentType"))?;
    let title = require_legacy_optional_string(get("title"), &format!("{field_name}.Title"))?;
    let wire_contracts = require_legacy_optional_wire_contracts(
        get("wireContracts"),
        &format!("{field_name}.WireContracts"),
    )?;
    let content_hash =
        require_legacy_string(get("contentHash"), &format!("{field_name}.ContentHash"))?;
    let schema_json =
        require_legacy_optional_string(get("schemaJson"), &format!("{field_name}.SchemaJson"))?;

    let kind = match kind.as_str() {
        "wire_message" => CultNetSchemaKind::WireMessage,
        "document_payload" => CultNetSchemaKind::DocumentPayload,
        "shared_contract" => CultNetSchemaKind::SharedContract,
        _ => {
            return Err(anyhow!(
                "{field_name}.Kind has unsupported schema kind {kind}"
            ));
        }
    };

    Ok(CultNetSchemaDescriptor {
        schema_id,
        kind,
        schema_version,
        document_type,
        title,
        wire_contracts,
        content_hash,
        schema_json,
    })
}

fn require_legacy_optional_string(
    value: Option<&rmpv::Value>,
    field_name: &str,
) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_nil() {
        return Ok(None);
    }
    Ok(Some(require_legacy_string(Some(value), field_name)?))
}

fn require_legacy_optional_wire_contracts(
    value: Option<&rmpv::Value>,
    field_name: &str,
) -> Result<Vec<CultNetWireContract>> {
    let Some(values) = require_legacy_optional_string_array(value, field_name)? else {
        return Ok(Vec::new());
    };

    values
        .into_iter()
        .map(|value| match value.as_str() {
            "cultnet.schema.v0" => Ok(CultNetWireContract::CultNetSchemaV0),
            "gamecult.networking.v0" => Ok(CultNetWireContract::GameCultNetworkingV0),
            _ => Err(anyhow!(
                "{field_name} contains unsupported wire contract {value}"
            )),
        })
        .collect()
}

fn legacy_bytes(input: &str, field_name: &str) -> Result<rmpv::Value> {
    if input.trim().is_empty() {
        return Err(anyhow!("{field_name} must be a non-empty base64url string"));
    }
    Ok(rmpv::Value::Binary(URL_SAFE_NO_PAD.decode(input)?))
}

fn legacy_optional_string_array(input: Option<&[String]>) -> rmpv::Value {
    match input {
        Some(values) => rmpv::Value::Array(
            values
                .iter()
                .map(|value| rmpv::Value::from(value.as_str()))
                .collect(),
        ),
        None => rmpv::Value::Nil,
    }
}

fn legacy_optional_schema_kind_array(input: Option<&[CultNetSchemaKind]>) -> rmpv::Value {
    match input {
        Some(values) => rmpv::Value::Array(
            values
                .iter()
                .map(|value| {
                    rmpv::Value::from(match value {
                        CultNetSchemaKind::WireMessage => "wire_message",
                        CultNetSchemaKind::DocumentPayload => "document_payload",
                        CultNetSchemaKind::SharedContract => "shared_contract",
                    })
                })
                .collect(),
        ),
        None => rmpv::Value::Nil,
    }
}

fn legacy_schema_descriptor(schema: &CultNetSchemaDescriptor) -> Result<rmpv::Value> {
    Ok(rmpv::Value::Map(vec![
        (
            rmpv::Value::from("schemaId"),
            rmpv::Value::from(schema.schema_id.as_str()),
        ),
        (
            rmpv::Value::from("kind"),
            rmpv::Value::from(match schema.kind {
                CultNetSchemaKind::WireMessage => "wire_message",
                CultNetSchemaKind::DocumentPayload => "document_payload",
                CultNetSchemaKind::SharedContract => "shared_contract",
            }),
        ),
        (
            rmpv::Value::from("schemaVersion"),
            schema
                .schema_version
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
        (
            rmpv::Value::from("documentType"),
            schema
                .document_type
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
        (
            rmpv::Value::from("title"),
            schema
                .title
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
        (
            rmpv::Value::from("wireContracts"),
            rmpv::Value::Array(
                schema
                    .wire_contracts
                    .iter()
                    .map(|value| {
                        rmpv::Value::from(match value {
                            CultNetWireContract::CultNetSchemaV0 => "cultnet.schema.v0",
                            CultNetWireContract::GameCultNetworkingV0 => "gamecult.networking.v0",
                        })
                    })
                    .collect(),
            ),
        ),
        (
            rmpv::Value::from("contentHash"),
            rmpv::Value::from(schema.content_hash.as_str()),
        ),
        (
            rmpv::Value::from("schemaJson"),
            schema
                .schema_json
                .as_deref()
                .map(rmpv::Value::from)
                .unwrap_or(rmpv::Value::Nil),
        ),
    ]))
}
