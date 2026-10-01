use serde::{Deserialize, Serialize};

use crate::{ManagementOperationV2, ManagementSnapshotV2};

pub const MANAGEMENT_PROJECTION_SCHEMA: &str =
    "crowsi://credential-authority/management-projection/v2";
pub const MANAGEMENT_PROJECTION_DOMAIN: &[u8] = b"CROWSI-CREDENTIAL-MANAGEMENT-PROJECTION-V2\0";
pub const MANAGEMENT_COMMAND_DOMAIN: &[u8] = b"CROWSI-CREDENTIAL-MANAGEMENT-COMMAND-V2\0";
pub const MAX_MANAGEMENT_WIRE_BYTES: usize = 262_144;
pub const MANAGEMENT_PROJECTION_MAX_TTL_SECONDS: u64 = 30;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "view", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum ManagementProjectionBodyV2 {
    Snapshot {
        snapshot: ManagementSnapshotV2,
    },
    Pending {
        operations: Vec<ManagementOperationV2>,
    },
    Operation {
        operation: ManagementOperationV2,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementProjectionV2 {
    pub schema: String,
    pub projection_id: String,
    pub request_id: String,
    pub command_digest_sha256: String,
    pub issuer: String,
    pub audience: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub opaque_account_ref: String,
    pub current_device_ref: String,
    pub current_session_ref: String,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub device_posture_state: String,
    pub device_posture_revision: u64,
    pub device_proof_key_ref: String,
    pub snapshot_revision: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub body: ManagementProjectionBodyV2,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementProjectionBinding<'a> {
    pub request_id: &'a str,
    pub command_digest_sha256: &'a str,
    pub issuer: &'a str,
    pub audience: &'a str,
    pub service_id: &'a str,
    pub pairwise_subject: &'a str,
    pub opaque_account_ref: &'a str,
    pub current_device_ref: &'a str,
    pub current_session_ref: &'a str,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub device_posture_state: &'a str,
    pub device_posture_revision: u64,
    pub device_proof_key_ref: &'a str,
    pub minimum_snapshot_revision: u64,
}
