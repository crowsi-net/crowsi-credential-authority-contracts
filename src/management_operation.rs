use serde::{Deserialize, Serialize};

use crate::WebAuthnOptionsV2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementOperationKind {
    DeviceTransfer,
    DeviceRevocation,
    SessionRevocation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementOperationState {
    AwaitingSourceUv,
    AwaitingTarget,
    AwaitingTargetUv,
    AwaitingIndependentApproval,
    AwaitingApprovalUv,
    AwaitingRevocationFinal,
    RevocationExecutionReserved,
    Executing,
    Unknown,
    Completed,
    Rejected,
    Cancelled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredActorRole {
    SourceDevice,
    TargetDevice,
    IndependentApproval,
    Authority,
    ReconcileOnly,
    NoActor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagementReasonCode {
    InvalidRequest,
    AuthorityUnavailable,
    IdentityEvidenceUnavailable,
    IdentityEvidenceInvalid,
    UserVerificationRejected,
    ActorMismatch,
    TargetProofRejected,
    IndependentApprovalRequired,
    EpochConflict,
    ReplayRejected,
    ProviderRejected,
    ProviderOutcomeUnknown,
    OperationUnknown,
    OperationExpired,
    OperationCancelled,
    StateConflict,
    ConfigurationRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorRequirementV2 {
    pub role: RequiredActorRole,
    pub required_actor_device_ref: Option<String>,
    pub required_approval_authority_ref: Option<String>,
    pub excluded_actor_device_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementOperationScopeV2 {
    DeviceTransfer {
        target_device_ref: String,
        credential_refs: Vec<String>,
        expected_source_device_revocation_epoch: u64,
    },
    DeviceRevocation {
        target_device_ref: String,
        expected_device_revocation_epoch: u64,
        revokes_session_refs: Vec<String>,
        rotates_credential_refs: Vec<String>,
        preserves_device_refs: Vec<String>,
    },
    SessionRevocation {
        target_session_ref: String,
        expected_session_revocation_epoch: u64,
        device_ref: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementOperationV2 {
    pub operation_id: String,
    pub kind: ManagementOperationKind,
    pub intent_digest_sha256: String,
    pub state: ManagementOperationState,
    pub state_revision: u64,
    pub created_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub source_device_ref: String,
    pub scope: ManagementOperationScopeV2,
    pub actor: ActorRequirementV2,
    pub webauthn_options: Option<WebAuthnOptionsV2>,
    pub reason: Option<ManagementReasonCode>,
    pub reconcile_digest: Option<String>,
}
