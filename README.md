# CultNet RS

`cultnet-rs` is the Rust sibling of `cultnet-ts`: typed MessagePack messages,
4-byte length-prefixed direct-pipe framing, CultLib-shaped security helpers, and
CultCache replication without making callers paw through raw envelopes like we
lost a bet.

The contract is intentionally boring:

- `cultnet.schema.v0` sends schema-versioned MessagePack objects.
- `gamecult.networking.v0` maps the legacy C# union shape explicitly.
- schema discovery uses explicit catalog request/response messages; no inbound
  auto-detect sludge.
- document put/delete/snapshot messages move typed CultCache entries.
- payloads are decoded through registered Rust types before entering the cache.

This crate is not an HTTP wrapper. It is the wire vocabulary Epiphany,
Ghostlight, VoidBot, and the rest of the swarm can share.

## Receipts

```powershell
cargo test
```

The initial tests prove:

- CultLib-compatible AES-GCM string encryption and HMAC session tokens
- 4-byte big-endian MessagePack framing
- schema-versioned message round trips
- legacy `gamecult.networking.v0` login mapping
- schema discovery catalog responses with canonical JSON schema hashes
- CultCache snapshot replication through registered typed documents

## Schema Discovery

`cultnet-rs` now ships a built-in schema registry for the shared swarm contract
surface:

- core wire messages
- legacy `gamecult.networking.v0` auth/sample payloads
- schema catalog request/response messages
- the canonical `ghostlight.agent-state` document payload schema

Use `builtin_schema_registry()` when you want the standard catalog, or register
your own closed-world schema set with `CultNetSchemaRegistry`. Discovery stays
explicit on purpose: peers advertise only the contracts they were compiled to
understand, the same way CultCache only consumes the document types you
registered instead of pretending polymorphism is a public park.
