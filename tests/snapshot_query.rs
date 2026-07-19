use anyhow::Result;
use cultnet_rs::{
    CultNetDocumentBinding, CultNetDocumentRegistry, CultNetMessage, CultNetRawDocumentRecord,
    CultNetRawPayloadEncoding, CultNetRawSnapshotQuery, CultNetReadOnlySnapshotPolicy,
    CultNetSnapshotRecordExpectation, CultNetSnapshotSourceExpectation, CultNetWireContract,
    decode_cultnet_message_from_slice, encode_cultnet_message_to_vec, query_read_only_raw_snapshot,
    serve_read_only_raw_snapshot,
};

const HEALTH_SCHEMA: &str = "idunn.managed_health_projection.v1";

fn registry() -> CultNetDocumentRegistry {
    let mut registry = CultNetDocumentRegistry::new();
    registry.register(CultNetDocumentBinding {
        schema_id: HEALTH_SCHEMA.to_string(),
        document_type: "idunn.managed-health-projection".to_string(),
        mutation_contract: None,
        payload_schema_version: Some(HEALTH_SCHEMA.to_string()),
    });
    registry
}

fn record(key: &str, payload: Vec<u8>) -> CultNetRawDocumentRecord {
    CultNetRawDocumentRecord {
        schema_id: HEALTH_SCHEMA.to_string(),
        record_key: key.to_string(),
        stored_at: "2026-07-19T20:00:00Z".to_string(),
        payload_encoding: CultNetRawPayloadEncoding::Messagepack,
        payload,
        source_runtime_id: Some("idunn@yggdrasil".to_string()),
        source_agent_id: Some("idunn".to_string()),
        source_role: Some("deployment-owner".to_string()),
        tags: Some(vec!["public-health".to_string()]),
    }
}

fn expectation(key: &str) -> CultNetSnapshotRecordExpectation {
    CultNetSnapshotRecordExpectation {
        schema_id: HEALTH_SCHEMA.to_string(),
        record_key: key.to_string(),
        source: CultNetSnapshotSourceExpectation {
            runtime_id: Some("idunn@yggdrasil".to_string()),
            agent_id: Some("idunn".to_string()),
            role: Some("deployment-owner".to_string()),
            tags: Some(vec!["public-health".to_string()]),
        },
    }
}

#[test]
fn canonical_wire_loop_returns_exact_stored_raw_record_without_cache_apply() -> Result<()> {
    let stored = record("epiphany-agent", vec![0x95, 0xc4, 0x02, 0xde, 0xad]);
    let source = vec![stored.clone(), record("not-public", vec![0x01])];
    let mut policy = CultNetReadOnlySnapshotPolicy::new();
    policy.allow(HEALTH_SCHEMA, "epiphany-agent")?;
    let query = CultNetRawSnapshotQuery::new("status-42", vec![expectation("epiphany-agent")])?;

    let received = query_read_only_raw_snapshot(&query, |request| {
        // This is the canonical transport loop: request and response both cross
        // the CultNet wire codec. Neither side receives a cache to mutate.
        let request_wire =
            encode_cultnet_message_to_vec(&request, CultNetWireContract::CultNetSchemaV0)?;
        let decoded_request =
            decode_cultnet_message_from_slice(&request_wire, CultNetWireContract::CultNetSchemaV0)?;
        let response =
            serve_read_only_raw_snapshot(&registry(), &policy, &source, &decoded_request)?;
        let response_wire =
            encode_cultnet_message_to_vec(&response, CultNetWireContract::CultNetSchemaV0)?;
        decode_cultnet_message_from_slice(&response_wire, CultNetWireContract::CultNetSchemaV0)
    })?;

    assert_eq!(received, vec![stored]);
    Ok(())
}

#[test]
fn server_filters_by_exact_policy_pair_and_request() -> Result<()> {
    let source = vec![record("epiphany-agent", vec![1]), record("odin", vec![2])];
    let mut policy = CultNetReadOnlySnapshotPolicy::new();
    policy.allow(HEALTH_SCHEMA, "epiphany-agent")?;
    let request = CultNetMessage::SnapshotRequest {
        message_id: "bounded".to_string(),
        schema_ids: Some(vec![HEALTH_SCHEMA.to_string()]),
        record_keys: Some(vec!["epiphany-agent".to_string(), "odin".to_string()]),
    };

    let response = serve_read_only_raw_snapshot(&registry(), &policy, &source, &request)?;
    let CultNetMessage::SnapshotResponseRaw { documents, .. } = response else {
        panic!("expected raw response");
    };
    assert_eq!(documents, vec![source[0].clone()]);
    Ok(())
}

#[test]
fn server_rejects_duplicate_request_terms_and_ambiguous_backing_records() -> Result<()> {
    let mut policy = CultNetReadOnlySnapshotPolicy::new();
    policy.allow(HEALTH_SCHEMA, "epiphany-agent")?;
    let duplicate_request = CultNetMessage::SnapshotRequest {
        message_id: "duplicate-request".to_string(),
        schema_ids: Some(vec![HEALTH_SCHEMA.to_string(), HEALTH_SCHEMA.to_string()]),
        record_keys: Some(vec!["epiphany-agent".to_string()]),
    };
    let error = serve_read_only_raw_snapshot(
        &registry(),
        &policy,
        &vec![record("epiphany-agent", vec![1])],
        &duplicate_request,
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate requested schema id"));

    let request = CultNetMessage::SnapshotRequest {
        message_id: "duplicate-source".to_string(),
        schema_ids: None,
        record_keys: None,
    };
    let duplicate = record("epiphany-agent", vec![1]);
    let error = serve_read_only_raw_snapshot(
        &registry(),
        &policy,
        &vec![duplicate.clone(), duplicate],
        &request,
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate record"));
    Ok(())
}

#[test]
fn query_rejects_duplicate_expectations_wrong_message_and_unrelated_message() -> Result<()> {
    let error = CultNetRawSnapshotQuery::new(
        "duplicate",
        vec![expectation("epiphany-agent"), expectation("epiphany-agent")],
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate requested record"));

    let query = CultNetRawSnapshotQuery::new("wanted", vec![expectation("epiphany-agent")])?;
    let error = query
        .accept_response(CultNetMessage::SnapshotResponseRaw {
            message_id: "somebody-elses-response".to_string(),
            documents: vec![],
        })
        .unwrap_err();
    assert!(error.to_string().contains("does not match request"));

    let error = query
        .accept_response(CultNetMessage::Error {
            error: "unrelated".to_string(),
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("expected cultnet.snapshot_response_raw.v0")
    );
    Ok(())
}

#[test]
fn query_rejects_unexpected_identity_duplicates_and_source_metadata() -> Result<()> {
    let query = CultNetRawSnapshotQuery::new("hostile", vec![expectation("epiphany-agent")])?;

    let error = query
        .accept_response(CultNetMessage::SnapshotResponseRaw {
            message_id: "hostile".to_string(),
            documents: vec![record("odin", vec![1])],
        })
        .unwrap_err();
    assert!(error.to_string().contains("unexpected record"));

    let document = record("epiphany-agent", vec![1]);
    let error = query
        .accept_response(CultNetMessage::SnapshotResponseRaw {
            message_id: "hostile".to_string(),
            documents: vec![document.clone(), document],
        })
        .unwrap_err();
    assert!(error.to_string().contains("duplicate record"));

    let mut forged = record("epiphany-agent", vec![1]);
    forged.source_runtime_id = Some("mallory".to_string());
    let error = query
        .accept_response(CultNetMessage::SnapshotResponseRaw {
            message_id: "hostile".to_string(),
            documents: vec![forged],
        })
        .unwrap_err();
    assert!(error.to_string().contains("unexpected source_runtime_id"));

    let mut forged = record("epiphany-agent", vec![1]);
    forged.tags = Some(vec!["private".to_string()]);
    let error = query
        .accept_response(CultNetMessage::SnapshotResponseRaw {
            message_id: "hostile".to_string(),
            documents: vec![forged],
        })
        .unwrap_err();
    assert!(error.to_string().contains("unexpected tags"));
    Ok(())
}

#[test]
fn server_rejects_unregistered_source_schema_even_when_not_exposed() -> Result<()> {
    let mut foreign = record("foreign", vec![1]);
    foreign.schema_id = "xenos.unregistered.v0".to_string();
    let request = CultNetMessage::SnapshotRequest {
        message_id: "unregistered".to_string(),
        schema_ids: None,
        record_keys: None,
    };
    let error = serve_read_only_raw_snapshot(
        &registry(),
        &CultNetReadOnlySnapshotPolicy::new(),
        &vec![foreign],
        &request,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unregistered schema"));
    Ok(())
}
