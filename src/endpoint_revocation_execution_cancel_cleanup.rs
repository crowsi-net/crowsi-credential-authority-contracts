use ihat_identity_assertion_contracts::{AuthorityRequestV1, SignedEvidenceV1};
use serde::{Deserialize, Serialize};

use crate::{ContractError, ManagementOperationV2};

pub const ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_CLEANUP_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-execution-cancellation-cleanup/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionCancellationCleanupV1 {
    pub schema: String,
    pub cleanup_id: String,
    pub cancel_finalize_request_sha256: String,
    pub cancellation_id: String,
    pub cancel_pending_command_digest_sha256: String,
    pub cancel_pending_response_digest_sha256: String,
    pub source_device_ref: String,
    pub cleanup_completed_revision: u64,
    pub cleanup_config_generation: u64,
    pub operation: ManagementOperationV2,
    pub snapshot_revision: u64,
    pub acknowledge_request: AuthorityRequestV1,
    pub token: SignedEvidenceV1,
    pub issuer: String,
    pub audience: String,
    pub config_generation: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub key_id: String,
    pub signature: String,
}

/// Strictly decodes one central cleanup-completion proof.
///
/// # Errors
/// Rejects empty, oversized, open, malformed, or invalid documents.
pub fn decode_endpoint_revocation_execution_cancellation_cleanup_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionCancellationCleanupV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value = serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_cancel_cleanup_validation::validate(&value)?;
    Ok(value)
}
