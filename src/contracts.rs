use anyhow::Result;
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CultNetWireContract {
    CultNetSchemaV0,
    GameCultNetworkingV0,
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
}

pub fn parse_cultnet_message(
    wire_value: &rmpv::Value,
    contract: CultNetWireContract,
) -> Result<CultNetMessage> {
    match contract {
        CultNetWireContract::CultNetSchemaV0 => {
            let json_value: Value = rmp_serde::from_slice(&rmp_serde::to_vec(wire_value)?)?;
            let message: CultNetMessage = serde_json::from_value(json_value)?;
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
        CultNetWireContract::CultNetSchemaV0 => Ok(rmp_serde::from_slice(&rmp_serde::to_vec(
            &serde_json::to_value(message)?,
        )?)?),
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
        let json_value: Value = rmp_serde::from_slice(bytes)?;
        let message: CultNetMessage = serde_json::from_value(json_value)?;
        validate_message(&message)?;
        return Ok(message);
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

fn legacy_bytes(input: &str, field_name: &str) -> Result<rmpv::Value> {
    if input.trim().is_empty() {
        return Err(anyhow!("{field_name} must be a non-empty base64url string"));
    }
    Ok(rmpv::Value::Binary(URL_SAFE_NO_PAD.decode(input)?))
}
