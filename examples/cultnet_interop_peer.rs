use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use cultcache_rs::CultCache;
use cultcache_rs::DatabaseEntry;
use cultcache_rs::SingleFileMessagePackBackingStore;
use cultnet_rs::CultNetDocumentBinding;
use cultnet_rs::CultNetDocumentRegistry;
use cultnet_rs::CultNetMessage;
use cultnet_rs::CultNetSchemaKind;
use cultnet_rs::CultNetSchemaRegistration;
use cultnet_rs::CultNetSchemaRegistry;
use cultnet_rs::CultNetWireContract;
use cultnet_rs::builtin_schema_registry;
use cultnet_rs::decode_cultnet_message_from_slice;
use cultnet_rs::encode_cultnet_message_to_vec;
use cultnet_rs::encode_frame;
use serde::Deserialize;
use serde::Serialize;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

const INTEROP_DOCUMENT_TYPE: &str = "cultnet.interop-note";
const INTEROP_SCHEMA_VERSION: &str = "cultnet.interop_note.v0";
const DISCOVERY_ANNOUNCE_SCHEMA_VERSION: &str = "cultnet.discovery_announce.v0";

#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "cultnet.interop-note", schema = "CultNetInteropNote")]
struct CultNetInteropNote {
    #[cultcache(key = 0)]
    schema_version: String,
    #[cultcache(key = 1)]
    document_id: String,
    #[cultcache(key = 2)]
    author_runtime_id: String,
    #[cultcache(key = 3)]
    title: String,
    #[cultcache(key = 4)]
    body: String,
    #[cultcache(key = 5)]
    tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "schemaVersion", rename_all = "camelCase")]
enum DiscoveryMessage {
    #[serde(rename = "cultnet.discovery_probe.v0", rename_all = "camelCase")]
    Probe {
        message_id: String,
        requester_runtime_id: String,
    },
    #[serde(rename = "cultnet.discovery_announce.v0", rename_all = "camelCase")]
    Announce {
        message_id: String,
        runtime_id: String,
        runtime_kind: String,
        display_name: String,
        agent_id: Option<String>,
        tcp_host: String,
        tcp_port: u16,
        wire_contract: String,
        supported_document_types: Vec<String>,
        supports_schema_catalog: bool,
    },
}

#[derive(Clone, Debug)]
struct PeerConfig {
    runtime_id: String,
    runtime_kind: String,
    display_name: String,
    agent_id: String,
    bind_host: String,
    advertise_host: String,
    tcp_port: u16,
    discovery_port: u16,
    discovery_group: Ipv4Addr,
    schema_path: String,
}

#[derive(Clone, Debug)]
struct DialConfig {
    runtime_id: String,
    runtime_kind: String,
    display_name: String,
    agent_id: String,
    target_host: String,
    target_port: u16,
    schema_path: String,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or_else(|| anyhow!("expected mode: serve | probe | dial"))?;
    let options = parse_args(args.collect());

    match mode.as_str() {
        "serve" => serve(parse_peer_config(&options)?)?,
        "probe" => probe(&options)?,
        "dial" => dial(parse_dial_config(&options)?)?,
        _ => return Err(anyhow!("unknown mode {mode}")),
    }

    Ok(())
}

fn serve(config: PeerConfig) -> Result<()> {
    let schema_registration = load_schema_registration(&config.schema_path)?;
    let mut schema_registry = builtin_schema_registry()?;
    schema_registry.register(schema_registration)?;

    let mut cache = CultCache::new();
    cache.register_entry_type::<CultNetInteropNote>()?;
    cache.add_generic_backing_store(SingleFileMessagePackBackingStore::new(runtime_store_path(
        &config.runtime_id,
    )));
    cache.pull_all_backing_stores()?;
    let note = build_note(&config.runtime_id, &config.display_name);
    cache.put(&note.document_id, &note)?;

    let mut document_registry = CultNetDocumentRegistry::new();
    document_registry.register(CultNetDocumentBinding::for_entry::<CultNetInteropNote>(
        Some(INTEROP_SCHEMA_VERSION.to_string()),
    ));

    let cache = Arc::new(Mutex::new(cache));
    let document_registry = Arc::new(document_registry);
    let schema_registry = Arc::new(schema_registry);
    let config = Arc::new(config);

    start_udp_discovery_server(config.clone())?;
    start_tcp_server(config.clone(), cache, document_registry, schema_registry)?;

    print_json(&serde_json::json!({
        "status": "ready",
        "mode": "serve",
        "runtimeId": config.runtime_id,
        "runtimeKind": config.runtime_kind,
        "tcpPort": config.tcp_port,
        "discoveryPort": config.discovery_port,
        "discoveryGroup": config.discovery_group.to_string(),
    }))?;

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn probe(options: &BTreeMap<String, String>) -> Result<()> {
    let runtime_id = require_arg(options, "runtime-id")?.to_string();
    let discovery_port = parse_u16_arg(options, "discovery-port")?;
    let discovery_group = parse_ipv4_arg(options, "discovery-group")?;
    let timeout_ms = parse_u64_arg(options, "timeout-ms").unwrap_or(1_500);
    let message_id = format!("{runtime_id}-{}", chrono::Utc::now().timestamp_millis());

    let socket = create_discovery_socket(0, false)?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let probe_message = DiscoveryMessage::Probe {
        message_id: message_id.clone(),
        requester_runtime_id: runtime_id.clone(),
    };
    let payload = rmp_serde::to_vec_named(&probe_message)?;
    socket.send_to(
        &payload,
        SocketAddr::V4(SocketAddrV4::new(discovery_group, discovery_port)),
    )?;

    let mut buffer = vec![0_u8; 4096];
    let mut found = BTreeMap::<String, serde_json::Value>::new();
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((len, _)) => {
                if let Ok(DiscoveryMessage::Announce {
                    message_id: response_message_id,
                    runtime_id,
                    runtime_kind,
                    display_name,
                    agent_id,
                    tcp_host,
                    tcp_port,
                    wire_contract,
                    supported_document_types,
                    supports_schema_catalog,
                }) = rmp_serde::from_slice::<DiscoveryMessage>(&buffer[..len])
                {
                    if response_message_id == message_id {
                        found.insert(
                            runtime_id.clone(),
                            serde_json::json!({
                                "schemaVersion": DISCOVERY_ANNOUNCE_SCHEMA_VERSION,
                                "messageId": response_message_id,
                                "runtimeId": runtime_id,
                                "runtimeKind": runtime_kind,
                                "displayName": display_name,
                                "agentId": agent_id,
                                "tcpHost": tcp_host,
                                "tcpPort": tcp_port,
                                "wireContract": wire_contract,
                                "supportedDocumentTypes": supported_document_types,
                                "supportsSchemaCatalog": supports_schema_catalog,
                            }),
                        );
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    print_json(&serde_json::json!({
        "mode": "probe",
        "runtimeId": runtime_id,
        "peers": found.into_values().collect::<Vec<_>>(),
    }))?;
    Ok(())
}

fn dial(config: DialConfig) -> Result<()> {
    let schema_registration = load_schema_registration(&config.schema_path)?;

    let mut cache = CultCache::new();
    cache.register_entry_type::<CultNetInteropNote>()?;
    cache.add_generic_backing_store(SingleFileMessagePackBackingStore::new(runtime_store_path(
        &format!("{}-dial", config.runtime_id),
    )));
    cache.pull_all_backing_stores()?;

    let mut document_registry = CultNetDocumentRegistry::new();
    document_registry.register(CultNetDocumentBinding::for_entry::<CultNetInteropNote>(
        Some(INTEROP_SCHEMA_VERSION.to_string()),
    ));

    let mut stream = TcpStream::connect((config.target_host.as_str(), config.target_port))
        .with_context(|| {
            format!(
                "failed to connect to {}:{}",
                config.target_host, config.target_port
            )
        })?;

    send_message(
        &mut stream,
        &CultNetMessage::Hello {
            runtime_id: config.runtime_id.clone(),
            runtime_kind: config.runtime_kind.clone(),
            agent_id: Some(config.agent_id.clone()),
            role: None,
            display_name: Some(config.display_name.clone()),
            supported_document_types: Some(vec![INTEROP_DOCUMENT_TYPE.to_string()]),
            supported_mutation_contracts: None,
            supported_message_versions: Some(vec![INTEROP_SCHEMA_VERSION.to_string()]),
            supports_schema_catalog: Some(true),
        },
    )?;

    let remote_hello = read_message(&mut stream)?;
    let remote_runtime_id = match &remote_hello {
        CultNetMessage::Hello { runtime_id, .. } => runtime_id.clone(),
        other => return Err(anyhow!("expected hello response, got {other:?}")),
    };

    send_message(
        &mut stream,
        &CultNetMessage::SchemaCatalogRequest {
            message_id: format!("{}-catalog", config.runtime_id),
            include_schema_json: Some(true),
            schema_ids: None,
            kinds: None,
        },
    )?;
    let catalog_response = read_message(&mut stream)?;
    let has_interop_schema = match &catalog_response {
        CultNetMessage::SchemaCatalogResponse { schemas, .. } => schemas.iter().any(|schema| {
            schema.schema_id == schema_registration.schema_id
                && schema.document_type.as_deref() == Some(INTEROP_DOCUMENT_TYPE)
        }),
        other => return Err(anyhow!("expected catalog response, got {other:?}")),
    };

    send_message(
        &mut stream,
        &CultNetMessage::SnapshotRequest {
            message_id: format!("{}-snapshot", config.runtime_id),
            document_types: Some(vec![INTEROP_DOCUMENT_TYPE.to_string()]),
            document_keys: None,
        },
    )?;
    let snapshot_response = read_message(&mut stream)?;
    let applied = document_registry
        .apply_raw_snapshot_response::<CultNetInteropNote>(&mut cache, &snapshot_response)?;
    let note = applied
        .into_iter()
        .find(|candidate| candidate.author_runtime_id == remote_runtime_id)
        .ok_or_else(|| anyhow!("did not receive an interop note from {remote_runtime_id}"))?;

    print_json(&serde_json::json!({
        "mode": "dial",
        "runtimeId": config.runtime_id,
        "targetHost": config.target_host,
        "targetPort": config.target_port,
        "remoteHello": {
            "schemaVersion": "cultnet.hello.v0",
            "runtimeId": remote_runtime_id,
        },
        "hasInteropSchema": has_interop_schema,
        "retrievedNote": {
            "schemaVersion": note.schema_version,
            "documentId": note.document_id,
            "authorRuntimeId": note.author_runtime_id,
            "title": note.title,
            "body": note.body,
            "tags": note.tags,
        },
    }))?;
    Ok(())
}

fn start_udp_discovery_server(config: Arc<PeerConfig>) -> Result<()> {
    let socket = create_discovery_socket(config.discovery_port, true)?;
    socket.join_multicast_v4(&config.discovery_group, &Ipv4Addr::UNSPECIFIED)?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;

    thread::spawn(move || {
        let mut buffer = vec![0_u8; 4096];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, remote)) => {
                    if let Ok(DiscoveryMessage::Probe {
                        message_id,
                        requester_runtime_id: _,
                    }) = rmp_serde::from_slice::<DiscoveryMessage>(&buffer[..len])
                    {
                        let announce = DiscoveryMessage::Announce {
                            message_id,
                            runtime_id: config.runtime_id.clone(),
                            runtime_kind: config.runtime_kind.clone(),
                            display_name: config.display_name.clone(),
                            agent_id: Some(config.agent_id.clone()),
                            tcp_host: config.advertise_host.clone(),
                            tcp_port: config.tcp_port,
                            wire_contract: "cultnet.schema.v0".to_string(),
                            supported_document_types: vec![INTEROP_DOCUMENT_TYPE.to_string()],
                            supports_schema_catalog: true,
                        };
                        if let Ok(payload) = rmp_serde::to_vec_named(&announce) {
                            let _ = socket.send_to(&payload, remote);
                        }
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
    });

    Ok(())
}

fn start_tcp_server(
    config: Arc<PeerConfig>,
    cache: Arc<Mutex<CultCache>>,
    document_registry: Arc<CultNetDocumentRegistry>,
    schema_registry: Arc<CultNetSchemaRegistry>,
) -> Result<()> {
    let listener =
        TcpListener::bind((config.bind_host.as_str(), config.tcp_port)).with_context(|| {
            format!(
                "failed to bind TCP listener on {}:{}",
                config.bind_host, config.tcp_port
            )
        })?;
    listener.set_nonblocking(false)?;

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            let config = config.clone();
            let cache = cache.clone();
            let document_registry = document_registry.clone();
            let schema_registry = schema_registry.clone();
            thread::spawn(move || {
                let _ =
                    handle_connection(stream, config, cache, document_registry, schema_registry);
            });
        }
    });

    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    config: Arc<PeerConfig>,
    cache: Arc<Mutex<CultCache>>,
    document_registry: Arc<CultNetDocumentRegistry>,
    schema_registry: Arc<CultNetSchemaRegistry>,
) -> Result<()> {
    loop {
        let message = match read_message(&mut stream) {
            Ok(message) => message,
            Err(error) if is_eof_like(&error) => break,
            Err(error) => return Err(error),
        };

        match message {
            CultNetMessage::Hello { .. } => {
                send_message(
                    &mut stream,
                    &CultNetMessage::Hello {
                        runtime_id: config.runtime_id.clone(),
                        runtime_kind: config.runtime_kind.clone(),
                        agent_id: Some(config.agent_id.clone()),
                        role: None,
                        display_name: Some(config.display_name.clone()),
                        supported_document_types: Some(vec![INTEROP_DOCUMENT_TYPE.to_string()]),
                        supported_mutation_contracts: None,
                        supported_message_versions: Some(vec![INTEROP_SCHEMA_VERSION.to_string()]),
                        supports_schema_catalog: Some(true),
                    },
                )?;
            }
            request @ CultNetMessage::SchemaCatalogRequest { .. } => {
                let response = schema_registry.create_catalog_response(&request)?;
                send_message(&mut stream, &response)?;
            }
            CultNetMessage::SnapshotRequest {
                message_id,
                document_types,
                document_keys,
            } => {
                let mut response = document_registry.create_raw_snapshot_response(
                    &cache.lock().expect("cache poisoned"),
                    message_id,
                    document_types.as_deref(),
                    document_keys.as_deref(),
                )?;
                if let CultNetMessage::SnapshotResponseRaw { documents, .. } = &mut response {
                    for document in documents.iter_mut() {
                        document.source_runtime_id = Some(config.runtime_id.clone());
                        document.source_agent_id = Some(config.agent_id.clone());
                        document.source_role = Some("peer".to_string());
                        document.tags =
                            Some(vec!["interop".to_string(), config.runtime_id.clone()]);
                    }
                }
                send_message(&mut stream, &response)?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn load_schema_registration(schema_path: &str) -> Result<CultNetSchemaRegistration> {
    let schema_json = fs::read_to_string(schema_path)
        .with_context(|| format!("failed to read schema {}", schema_path))?;
    let parsed: serde_json::Value = serde_json::from_str(&schema_json)
        .with_context(|| format!("failed to parse schema {}", schema_path))?;
    let schema_id = parsed
        .get("$id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("schema {} is missing $id", schema_path))?
        .to_string();
    let title = parsed
        .get("title")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);

    Ok(CultNetSchemaRegistration {
        schema_id,
        kind: CultNetSchemaKind::DocumentPayload,
        wire_contracts: vec![CultNetWireContract::CultNetSchemaV0],
        schema_version: Some(INTEROP_SCHEMA_VERSION.to_string()),
        document_type: Some(INTEROP_DOCUMENT_TYPE.to_string()),
        title,
        schema_json: Some(schema_json),
    })
}

fn build_note(runtime_id: &str, display_name: &str) -> CultNetInteropNote {
    CultNetInteropNote {
        schema_version: INTEROP_SCHEMA_VERSION.to_string(),
        document_id: format!("note:{runtime_id}"),
        author_runtime_id: runtime_id.to_string(),
        title: format!("{display_name} keeps a little note"),
        body: format!(
            "{runtime_id} can move CultNet state without begging the gods for translation."
        ),
        tags: vec![
            runtime_id.to_string(),
            "interop".to_string(),
            "cultnet".to_string(),
        ],
    }
}

fn send_message(stream: &mut TcpStream, message: &CultNetMessage) -> Result<()> {
    let payload = encode_cultnet_message_to_vec(message, CultNetWireContract::CultNetSchemaV0)?;
    let frame = encode_frame(&payload)?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn read_message(stream: &mut TcpStream) -> Result<CultNetMessage> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let payload_len = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    decode_cultnet_message_from_slice(&payload, CultNetWireContract::CultNetSchemaV0)
}

fn is_eof_like(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
}

fn create_discovery_socket(port: u16, _join_group: bool) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
    let socket = UdpSocket::from(socket);
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_nonblocking(false)?;
    Ok(socket)
}

fn parse_peer_config(options: &BTreeMap<String, String>) -> Result<PeerConfig> {
    Ok(PeerConfig {
        runtime_id: require_arg(options, "runtime-id")?.to_string(),
        runtime_kind: require_arg(options, "runtime-kind")?.to_string(),
        display_name: require_arg(options, "display-name")?.to_string(),
        agent_id: require_arg(options, "agent-id")?.to_string(),
        bind_host: options
            .get("bind-host")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        advertise_host: require_arg(options, "advertise-host")?.to_string(),
        tcp_port: parse_u16_arg(options, "tcp-port")?,
        discovery_port: parse_u16_arg(options, "discovery-port")?,
        discovery_group: parse_ipv4_arg(options, "discovery-group")?,
        schema_path: require_arg(options, "schema-path")?.to_string(),
    })
}

fn parse_dial_config(options: &BTreeMap<String, String>) -> Result<DialConfig> {
    Ok(DialConfig {
        runtime_id: require_arg(options, "runtime-id")?.to_string(),
        runtime_kind: require_arg(options, "runtime-kind")?.to_string(),
        display_name: require_arg(options, "display-name")?.to_string(),
        agent_id: require_arg(options, "agent-id")?.to_string(),
        target_host: require_arg(options, "target-host")?.to_string(),
        target_port: parse_u16_arg(options, "target-port")?,
        schema_path: require_arg(options, "schema-path")?.to_string(),
    })
}

fn parse_args(args: Vec<String>) -> BTreeMap<String, String> {
    let mut parsed = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if !token.starts_with("--") {
            index += 1;
            continue;
        }
        let name = token.trim_start_matches("--").to_string();
        let value = args
            .get(index + 1)
            .cloned()
            .unwrap_or_else(|| panic!("missing value for --{name}"));
        parsed.insert(name, value);
        index += 2;
    }
    parsed
}

fn require_arg<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing required argument --{name}"))
}

fn parse_u16_arg(options: &BTreeMap<String, String>, name: &str) -> Result<u16> {
    require_arg(options, name)?
        .parse::<u16>()
        .with_context(|| format!("argument --{name} must be a u16"))
}

fn parse_u64_arg(options: &BTreeMap<String, String>, name: &str) -> Option<u64> {
    options
        .get(name)
        .map(|value| value.parse::<u64>().expect("u64 arg"))
}

fn parse_ipv4_arg(options: &BTreeMap<String, String>, name: &str) -> Result<Ipv4Addr> {
    require_arg(options, name)?
        .parse::<Ipv4Addr>()
        .with_context(|| format!("argument --{name} must be an IPv4 address"))
}

fn runtime_store_path(runtime_id: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("cultnet-rs-interop-{runtime_id}.msgpack"))
}

fn print_json(value: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
