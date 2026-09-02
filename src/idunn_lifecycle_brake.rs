use anyhow::{Result, bail};
use cultcache_rs::DatabaseEntry;

pub const IDUNN_LIFECYCLE_BRAKE_SCHEMA: &str = "idunn.lifecycle_brake.v1";
pub const IDUNN_LIFECYCLE_BRAKE_TYPE: &str = "idunn.lifecycle_brake";
pub const IDUNN_LIFECYCLE_BRAKE_AUTHORITY: &str = "idunn.root";
pub const IDUNN_LIFECYCLE_BRAKE_SCOPE: &str = "continuity-restart";

/// Root-owned, per-target continuity brake. This document has no authority over
/// Idunn startup, deployment, route admission, or any target other than the one
/// named in `target`.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "idunn.lifecycle_brake", schema = "idunn.lifecycle_brake.v1")]
pub struct IdunnLifecycleBrakeRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub authority: String,
    #[cultcache(key = 2)]
    pub runtime_id: String,
    #[cultcache(key = 3)]
    pub target: String,
    #[cultcache(key = 4)]
    pub scope: String,
    #[cultcache(key = 5)]
    pub status: String,
    #[cultcache(key = 6)]
    pub reason: String,
    #[cultcache(key = 7)]
    pub updated_at_unix_millis: u64,
    #[cultcache(key = 8)]
    pub released_until_unix_millis: Option<u64>,
}

impl IdunnLifecycleBrakeRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDUNN_LIFECYCLE_BRAKE_SCHEMA {
            bail!("lifecycle brake schema is unsupported");
        }
        identifier(&self.authority, "authority")?;
        identifier(&self.runtime_id, "runtime id")?;
        identifier(&self.target, "target")?;
        identifier(&self.scope, "scope")?;
        identifier(&self.reason, "reason")?;
        if !matches!(self.status.as_str(), "engaged" | "released")
            || self.updated_at_unix_millis == 0
        {
            bail!("lifecycle brake status or update time is invalid");
        }
        if self.status == "engaged" && self.released_until_unix_millis.is_some() {
            bail!("engaged lifecycle brake cannot carry a release expiry");
        }
        if self
            .released_until_unix_millis
            .is_some_and(|expires| expires <= self.updated_at_unix_millis)
        {
            bail!("lifecycle brake release expiry is not after its update");
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn decode_canonical(payload: &[u8]) -> Result<Self> {
        if messagepack_array_len(payload) != Some(9) {
            bail!("lifecycle brake is not the 9-field positional contract");
        }
        let value: Self = rmp_serde::from_slice(payload)?;
        value.validate()?;
        if rmp_serde::to_vec(&value)? != payload {
            bail!("lifecycle brake encoding is not canonical");
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum IdunnLifecycleBrakeObservation<'a> {
    Missing,
    Corrupt,
    Present(&'a IdunnLifecycleBrakeRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdunnLifecycleBrakeDenial {
    Corrupt,
    Foreign,
    WrongRuntime,
    WrongTarget,
    Engaged,
    Expired,
}

/// Decide only whether Idunn may restart one already-admitted target to keep it
/// alive. Absence is the default allow state; a present record must bind the
/// exact Idunn runtime and target and must be explicitly released.
pub fn evaluate_idunn_continuity_restart(
    observation: IdunnLifecycleBrakeObservation<'_>,
    runtime_id: &str,
    target: &str,
    now_unix_millis: u64,
) -> std::result::Result<(), IdunnLifecycleBrakeDenial> {
    let record = match observation {
        IdunnLifecycleBrakeObservation::Missing => return Ok(()),
        IdunnLifecycleBrakeObservation::Corrupt => {
            return Err(IdunnLifecycleBrakeDenial::Corrupt);
        }
        IdunnLifecycleBrakeObservation::Present(record) => record,
    };
    if record.validate().is_err() {
        return Err(IdunnLifecycleBrakeDenial::Corrupt);
    }
    if record.authority != IDUNN_LIFECYCLE_BRAKE_AUTHORITY
        || record.scope != IDUNN_LIFECYCLE_BRAKE_SCOPE
    {
        return Err(IdunnLifecycleBrakeDenial::Foreign);
    }
    if record.runtime_id != runtime_id {
        return Err(IdunnLifecycleBrakeDenial::WrongRuntime);
    }
    if record.target != target {
        return Err(IdunnLifecycleBrakeDenial::WrongTarget);
    }
    if record.status == "engaged" {
        return Err(IdunnLifecycleBrakeDenial::Engaged);
    }
    if record
        .released_until_unix_millis
        .is_some_and(|expires| now_unix_millis >= expires)
    {
        return Err(IdunnLifecycleBrakeDenial::Expired);
    }
    Ok(())
}

fn identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("{label} is empty, oversized, or contains control characters");
    }
    Ok(())
}

fn messagepack_array_len(payload: &[u8]) -> Option<usize> {
    match *payload.first()? {
        marker @ 0x90..=0x9f => Some((marker & 0x0f) as usize),
        0xdc if payload.len() >= 3 => Some(u16::from_be_bytes([payload[1], payload[2]]) as usize),
        0xdd if payload.len() >= 5 => {
            Some(u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn released() -> IdunnLifecycleBrakeRecord {
        IdunnLifecycleBrakeRecord {
            schema_version: IDUNN_LIFECYCLE_BRAKE_SCHEMA.into(),
            authority: IDUNN_LIFECYCLE_BRAKE_AUTHORITY.into(),
            runtime_id: "idunn-yggdrasil".into(),
            target: "ghostlight".into(),
            scope: IDUNN_LIFECYCLE_BRAKE_SCOPE.into(),
            status: "released".into(),
            reason: "continuity restart permitted".into(),
            updated_at_unix_millis: 100,
            released_until_unix_millis: None,
        }
    }

    fn evaluate(
        observation: IdunnLifecycleBrakeObservation<'_>,
        target: &str,
        now: u64,
    ) -> std::result::Result<(), IdunnLifecycleBrakeDenial> {
        evaluate_idunn_continuity_restart(observation, "idunn-yggdrasil", target, now)
    }

    #[test]
    fn lifecycle_brake_round_trips_only_as_the_canonical_positional_contract() -> Result<()> {
        let value = released();
        let encoded = value.canonical_bytes()?;
        assert_eq!(encoded[0], 0x99);
        assert_eq!(
            IdunnLifecycleBrakeRecord::decode_canonical(&encoded)?,
            value
        );

        let mut noncanonical = vec![0xdc, 0, 9];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(IdunnLifecycleBrakeRecord::decode_canonical(&noncanonical).is_err());

        let mut extended = encoded;
        extended[0] = 0x9a;
        extended.push(0xc0);
        assert!(IdunnLifecycleBrakeRecord::decode_canonical(&extended).is_err());
        Ok(())
    }

    #[test]
    fn absence_and_explicit_release_allow_only_the_named_continuity_restart() {
        assert_eq!(
            evaluate(IdunnLifecycleBrakeObservation::Missing, "ghostlight", 500),
            Ok(())
        );

        let mut value = released();
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                500
            ),
            Ok(())
        );
        value.released_until_unix_millis = Some(900);
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                899
            ),
            Ok(())
        );
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                900
            ),
            Err(IdunnLifecycleBrakeDenial::Expired)
        );
        assert_eq!(
            evaluate(IdunnLifecycleBrakeObservation::Missing, "odin", 900),
            Ok(())
        );
        assert_eq!(
            evaluate(IdunnLifecycleBrakeObservation::Present(&value), "odin", 500),
            Err(IdunnLifecycleBrakeDenial::WrongTarget)
        );
    }

    #[test]
    fn corrupt_foreign_wrong_runtime_and_wrong_target_records_deny() {
        assert_eq!(
            evaluate(IdunnLifecycleBrakeObservation::Corrupt, "ghostlight", 500),
            Err(IdunnLifecycleBrakeDenial::Corrupt)
        );

        let mut value = released();
        value.status = "paused".into();
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                500
            ),
            Err(IdunnLifecycleBrakeDenial::Corrupt)
        );

        let mut value = released();
        value.authority = "service-owned".into();
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                500
            ),
            Err(IdunnLifecycleBrakeDenial::Foreign)
        );

        let mut value = released();
        value.scope = "deployment".into();
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                500
            ),
            Err(IdunnLifecycleBrakeDenial::Foreign)
        );

        let value = released();
        assert_eq!(
            evaluate_idunn_continuity_restart(
                IdunnLifecycleBrakeObservation::Present(&value),
                "idunn-nightwing",
                "ghostlight",
                500
            ),
            Err(IdunnLifecycleBrakeDenial::WrongRuntime)
        );
        assert_eq!(
            evaluate(IdunnLifecycleBrakeObservation::Present(&value), "odin", 500),
            Err(IdunnLifecycleBrakeDenial::WrongTarget)
        );
    }

    #[test]
    fn engaged_always_denies_and_cannot_smuggle_a_release_expiry() {
        let mut value = released();
        value.status = "engaged".into();
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                500
            ),
            Err(IdunnLifecycleBrakeDenial::Engaged)
        );
        value.released_until_unix_millis = Some(900);
        assert_eq!(
            evaluate(
                IdunnLifecycleBrakeObservation::Present(&value),
                "ghostlight",
                500
            ),
            Err(IdunnLifecycleBrakeDenial::Corrupt)
        );
    }
}
