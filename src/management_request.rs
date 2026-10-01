use serde::{Deserialize, Serialize};

use crate::WebAuthnAssertionV2;

pub const MANAGEMENT_REQUEST_SCHEMA: &str = "crowsi://credential-authority/management-request/v2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementIntentV2 {
    DeviceTransfer {
        service_id: String,
        target_device_ref: String,
        credential_refs: Vec<String>,
        expected_snapshot_revision: u64,
        nonce: String,
    },
    DeviceRevocation {
        service_id: String,
        target_device_ref: String,
        expected_device_revocation_epoch: u64,
        expected_snapshot_revision: u64,
        nonce: String,
    },
    SessionRevocation {
        service_id: String,
        target_session_ref: String,
        expected_session_revocation_epoch: u64,
        expected_snapshot_revision: u64,
        nonce: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementCommandV2 {
    Snapshot {
        service_id: String,
    },
    SourceOptions {
        intent: ManagementIntentV2,
    },
    SourceApprove {
        operation_id: String,
        expected_state_revision: u64,
        attempt_id: String,
        assertion: WebAuthnAssertionV2,
    },
    PendingList {
        service_id: String,
    },
    TargetOptions {
        operation_id: String,
        expected_state_revision: u64,
    },
    TargetApprove {
        operation_id: String,
        expected_state_revision: u64,
        attempt_id: String,
        assertion: WebAuthnAssertionV2,
    },
    ApprovalOptions {
        operation_id: String,
        expected_state_revision: u64,
    },
    ApproveRevocation {
        operation_id: String,
        expected_state_revision: u64,
        attempt_id: String,
        assertion: WebAuthnAssertionV2,
    },
    Cancel {
        operation_id: String,
        expected_state_revision: u64,
    },
    Reconcile {
        operation_id: String,
        expected_state_revision: u64,
        reconcile_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementRequestV2 {
    pub schema: String,
    pub request_id: String,
    pub command: ManagementCommandV2,
}
