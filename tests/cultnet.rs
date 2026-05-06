use anyhow::Result;
use chrono::Duration;
use cultcache_rs::CultCache;
use cultcache_rs::DatabaseEntry;
use cultcache_rs::SingleFileMessagePackBackingStore;
use cultnet_rs::CultNetClientSecurityOptions;
use cultnet_rs::CultNetDocumentBinding;
use cultnet_rs::CultNetDocumentPutOptions;
use cultnet_rs::CultNetDocumentRegistry;
use cultnet_rs::CultNetMessage;
use cultnet_rs::CultNetSchemaKind;
use cultnet_rs::CultNetSchemaRegistry;
use cultnet_rs::CultNetSecret;
use cultnet_rs::CultNetServerSecurityOptions;
use cultnet_rs::CultNetWireContract;
use cultnet_rs::LengthPrefixedMessageFramer;
use cultnet_rs::builtin_schema_registry;
use cultnet_rs::decode_cultnet_message_from_slice;
use cultnet_rs::encode_cultnet_message_for_wire;
use cultnet_rs::encode_cultnet_message_to_vec;
use cultnet_rs::encode_frame;
use pretty_assertions::assert_eq;

const TS_HELLO_FRAME: &[u8] = include_bytes!("fixtures/cultnet-ts-hello.frame");
const TS_LEGACY_LOGIN_FRAME: &[u8] = include_bytes!("fixtures/cultnet-ts-legacy-login.frame");

#[derive(Clone, Debug, PartialEq, DatabaseEntry)]
#[cultcache(
    type = "ghostlight.agent-state",
    schema = "GhostlightAgentStateFixture"
)]
struct GhostlightAgentStateFixture {
    #[cultcache(key = 0)]
    schema_version: String,
    #[cultcache(key = 1)]
    agent_id: String,
    #[cultcache(key = 2)]
    display_name: String,
}

#[test]
fn security_helpers_round_trip_encrypted_strings_and_validate_sessions() -> Result<()> {
    let server_security = CultNetServerSecurityOptions::development();
    let client_security = server_security.to_client_options();
    let nonce = CultNetSecret::new_nonce();
    let encrypted = CultNetSecret::encrypt_string(Some("hello"), &nonce, &client_security)?
        .expect("non-empty input encrypts");
    assert_eq!(
        CultNetSecret::decrypt_string(Some(&encrypted), Some(&nonce), &server_security)?,
        Some("hello".to_string())
    );

    let token = CultNetSecret::create_session_token(
        "runtime-face",
        chrono::Utc::now() + Duration::minutes(1),
        &server_security,
    )?;
    let validated = CultNetSecret::try_validate_session_token(Some(&token), &server_security)?
        .expect("token validates before expiry");
    assert_eq!(validated.user_id, "runtime-face");
    Ok(())
}

#[test]
fn cultnet_schema_messages_round_trip_through_messagepack_frames() -> Result<()> {
    let message = CultNetMessage::Hello {
        runtime_id: "voidbot-main".to_string(),
        runtime_kind: "rust-worker".to_string(),
        agent_id: Some("void".to_string()),
        role: None,
        display_name: Some("Void".to_string()),
        supported_document_types: Some(vec!["ghostlight.agent-state".to_string()]),
        supported_message_versions: None,
        supports_schema_catalog: Some(true),
    };
    let payload = encode_cultnet_message_to_vec(&message, CultNetWireContract::CultNetSchemaV0)?;
    let frame = encode_frame(&payload)?;
    assert_eq!(&frame[..4], &(payload.len() as u32).to_be_bytes());

    let mut framer = LengthPrefixedMessageFramer::new();
    assert!(framer.push(&frame[..2]).is_empty());
    let frames = framer.push(&frame[2..]);
    assert_eq!(frames.len(), 1);
    let decoded =
        decode_cultnet_message_from_slice(&frames[0], CultNetWireContract::CultNetSchemaV0)?;
    assert_eq!(decoded, message);
    Ok(())
}

#[test]
fn legacy_gamecult_networking_contract_round_trips_login_union() -> Result<()> {
    let message = CultNetMessage::Login {
        nonce: CultNetSecret::to_base64_url(b"nonce"),
        auth: CultNetSecret::to_base64_url(b"auth"),
        password: CultNetSecret::to_base64_url(b"password"),
    };
    let wire =
        encode_cultnet_message_for_wire(&message, CultNetWireContract::GameCultNetworkingV0)?;
    let items = wire.as_array().expect("legacy union is an array");
    assert_eq!(items[0].as_i64(), Some(0));
    assert_eq!(
        items[1].as_array().unwrap()[0].as_slice(),
        Some(&b"nonce"[..])
    );

    let bytes = rmp_serde::to_vec(&wire)?;
    let decoded =
        decode_cultnet_message_from_slice(&bytes, CultNetWireContract::GameCultNetworkingV0)?;
    assert_eq!(decoded, message);
    Ok(())
}

#[test]
fn rust_decodes_typescript_generated_cultnet_frames() -> Result<()> {
    let mut framer = LengthPrefixedMessageFramer::new();
    let hello_frames = framer.push(TS_HELLO_FRAME);
    assert_eq!(hello_frames.len(), 1);
    let hello =
        decode_cultnet_message_from_slice(&hello_frames[0], CultNetWireContract::CultNetSchemaV0)?;
    assert_eq!(
        hello,
        CultNetMessage::Hello {
            runtime_id: "voidbot-main".to_string(),
            runtime_kind: "node-worker".to_string(),
            agent_id: Some("void".to_string()),
            role: None,
            display_name: Some("Void".to_string()),
            supported_document_types: Some(vec!["ghostlight.agent-state".to_string()]),
            supported_message_versions: None,
            supports_schema_catalog: None,
        }
    );

    let mut framer = LengthPrefixedMessageFramer::new();
    let login_frames = framer.push(TS_LEGACY_LOGIN_FRAME);
    assert_eq!(login_frames.len(), 1);
    let login = decode_cultnet_message_from_slice(
        &login_frames[0],
        CultNetWireContract::GameCultNetworkingV0,
    )?;
    assert_eq!(
        login,
        CultNetMessage::Login {
            nonce: "bm9uY2U".to_string(),
            auth: "YXV0aA".to_string(),
            password: "cGFzc3dvcmQ".to_string(),
        }
    );
    Ok(())
}

#[test]
fn document_registry_replicates_typed_cultcache_state() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let origin_store = temp.path().join("origin.msgpack");
    let target_store = temp.path().join("target.msgpack");
    let payload = GhostlightAgentStateFixture {
        schema_version: "ghostlight.agent_state.v0".to_string(),
        agent_id: "epiphany.face".to_string(),
        display_name: "Face".to_string(),
    };

    let mut registry = CultNetDocumentRegistry::new();
    registry.register(CultNetDocumentBinding::for_entry::<
        GhostlightAgentStateFixture,
    >(Some("ghostlight.agent_state.v0".to_string())));

    let mut origin = CultCache::new();
    origin.register_entry_type::<GhostlightAgentStateFixture>()?;
    origin.add_generic_backing_store(SingleFileMessagePackBackingStore::new(&origin_store));
    origin.pull_all_backing_stores()?;
    origin.put("epiphany.face", &payload)?;

    let snapshot = registry.create_snapshot_response(&origin, "snapshot-1", None, None)?;

    let mut target = CultCache::new();
    target.register_entry_type::<GhostlightAgentStateFixture>()?;
    target.add_generic_backing_store(SingleFileMessagePackBackingStore::new(&target_store));
    target.pull_all_backing_stores()?;
    let applied =
        registry.apply_snapshot_response::<GhostlightAgentStateFixture>(&mut target, &snapshot)?;
    assert_eq!(applied, vec![payload.clone()]);
    assert_eq!(
        target.get_required::<GhostlightAgentStateFixture>("epiphany.face")?,
        payload
    );

    let direct_put = registry.create_document_put_message(
        "put-1",
        "epiphany.face",
        &GhostlightAgentStateFixture {
            display_name: "Face Prime".to_string(),
            ..payload
        },
        CultNetDocumentPutOptions::default(),
    )?;
    let updated = registry
        .apply_document_put_message::<GhostlightAgentStateFixture>(&mut target, &direct_put)?;
    assert_eq!(updated.display_name, "Face Prime");
    Ok(())
}

#[test]
fn raw_snapshot_replication_preserves_messagepack_payload_bytes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let origin_store = temp.path().join("origin-raw.msgpack");
    let target_store = temp.path().join("target-raw.msgpack");
    let payload = GhostlightAgentStateFixture {
        schema_version: "ghostlight.agent_state.v0".to_string(),
        agent_id: "epiphany.face".to_string(),
        display_name: "Face".to_string(),
    };

    let mut registry = CultNetDocumentRegistry::new();
    registry.register(CultNetDocumentBinding::for_entry::<
        GhostlightAgentStateFixture,
    >(Some("ghostlight.agent_state.v0".to_string())));

    let mut origin = CultCache::new();
    origin.register_entry_type::<GhostlightAgentStateFixture>()?;
    origin.add_generic_backing_store(SingleFileMessagePackBackingStore::new(&origin_store));
    origin.pull_all_backing_stores()?;
    origin.put("epiphany.face", &payload)?;

    let raw_snapshot =
        registry.create_raw_snapshot_response(&origin, "raw-snapshot-1", None, None)?;
    let source_envelope =
        origin.get_required_envelope::<GhostlightAgentStateFixture>("epiphany.face")?;

    let mut target = CultCache::new();
    target.register_entry_type::<GhostlightAgentStateFixture>()?;
    target.add_generic_backing_store(SingleFileMessagePackBackingStore::new(&target_store));
    target.pull_all_backing_stores()?;
    let applied = registry
        .apply_raw_snapshot_response::<GhostlightAgentStateFixture>(&mut target, &raw_snapshot)?;
    let target_envelope =
        target.get_required_envelope::<GhostlightAgentStateFixture>("epiphany.face")?;

    assert_eq!(applied, vec![payload.clone()]);
    assert_eq!(target_envelope.payload, source_envelope.payload);
    assert_eq!(
        target.get_required::<GhostlightAgentStateFixture>("epiphany.face")?,
        payload
    );
    Ok(())
}

#[test]
fn client_security_keeps_the_connection_key_visible_without_exposing_cipher_logic() -> Result<()> {
    let options = CultNetClientSecurityOptions::development();
    assert_eq!(options.connection_key, "gamecult-dev-connection-key");
    assert_ne!(options.encryption_key(), [0_u8; 32]);
    Ok(())
}

#[test]
fn builtin_schema_registry_advertises_canonical_ghostlight_schema_without_inline_body_by_default()
-> Result<()> {
    let registry = builtin_schema_registry()?;
    let response = registry.create_catalog_response(&CultNetMessage::SchemaCatalogRequest {
        message_id: "catalog-1".to_string(),
        include_schema_json: None,
        schema_ids: None,
        kinds: None,
    })?;

    let CultNetMessage::SchemaCatalogResponse { schemas, .. } = response else {
        panic!("expected catalog response");
    };

    let ghostlight = schemas
        .iter()
        .find(|schema| schema.document_type.as_deref() == Some("ghostlight.agent-state"))
        .expect("ghostlight agent-state schema is advertised");

    assert_eq!(ghostlight.kind, CultNetSchemaKind::DocumentPayload);
    assert_eq!(
        ghostlight.schema_version.as_deref(),
        Some("ghostlight.agent_state.v0")
    );
    assert_eq!(ghostlight.schema_json, None);
    assert!(!ghostlight.content_hash.is_empty());
    Ok(())
}

#[test]
fn schema_discovery_round_trips_over_legacy_gamecult_contract_when_inline_schemas_are_requested()
-> Result<()> {
    let registry = {
        let mut registry = CultNetSchemaRegistry::new();
        registry.register(cultnet_rs::CultNetSchemaRegistration {
            schema_id: "https://example.test/contracts/example.schema.json".to_string(),
            kind: CultNetSchemaKind::SharedContract,
            wire_contracts: vec![
                CultNetWireContract::CultNetSchemaV0,
                CultNetWireContract::GameCultNetworkingV0,
            ],
            schema_version: None,
            document_type: None,
            title: Some("Example Schema".to_string()),
            schema_json: Some(
                r#"{
                    "$schema":"https://json-schema.org/draft/2020-12/schema",
                    "$id":"https://example.test/contracts/example.schema.json",
                    "title":"Example Schema",
                    "type":"object",
                    "properties":{"value":{"type":"string"}},
                    "required":["value"],
                    "additionalProperties":false
                }"#
                .to_string(),
            ),
        })?;
        registry
    };

    let response = registry.create_catalog_response(&CultNetMessage::SchemaCatalogRequest {
        message_id: "catalog-legacy".to_string(),
        include_schema_json: Some(true),
        schema_ids: None,
        kinds: None,
    })?;
    let wire =
        encode_cultnet_message_for_wire(&response, CultNetWireContract::GameCultNetworkingV0)?;
    let bytes = rmp_serde::to_vec(&wire)?;
    let decoded =
        decode_cultnet_message_from_slice(&bytes, CultNetWireContract::GameCultNetworkingV0)?;

    let CultNetMessage::SchemaCatalogResponse {
        message_id,
        schemas,
    } = decoded
    else {
        panic!("expected legacy schema catalog response");
    };

    assert_eq!(message_id, "catalog-legacy");
    assert_eq!(
        schemas[0].schema_id,
        "https://example.test/contracts/example.schema.json"
    );
    assert!(
        schemas[0]
            .schema_json
            .as_deref()
            .is_some_and(|schema| schema.contains("\"value\""))
    );
    Ok(())
}
