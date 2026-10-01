use serde::{Deserialize, Serialize};

use crate::ManagementOperationV2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialClassV2 {
    OperationOnly,
    DelegatedToken,
    Certificate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementLifecycleV2 {
    Active,
    Pending,
    Revoked,
    Closed,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementDeviceV2 {
    pub device_ref: String,
    pub status: ManagementLifecycleV2,
    pub device_revocation_epoch: u64,
    pub posture_revision: u64,
    pub session_refs: Vec<String>,
    pub created_at_rfc3339: String,
    pub updated_at_rfc3339: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementSessionV2 {
    pub session_ref: String,
    pub device_ref: String,
    pub status: ManagementLifecycleV2,
    pub session_revocation_epoch: u64,
    pub issued_at_rfc3339: String,
    pub expires_at_rfc3339: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementCredentialV2 {
    pub credential_ref: String,
    pub provider: String,
    pub class: CredentialClassV2,
    pub revision: u64,
    pub status: ManagementLifecycleV2,
    pub assigned_device_refs: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at_rfc3339: String,
    pub updated_at_rfc3339: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementSnapshotV2 {
    pub devices: Vec<ManagementDeviceV2>,
    pub sessions: Vec<ManagementSessionV2>,
    pub credentials: Vec<ManagementCredentialV2>,
    pub pending_operations: Vec<ManagementOperationV2>,
}
