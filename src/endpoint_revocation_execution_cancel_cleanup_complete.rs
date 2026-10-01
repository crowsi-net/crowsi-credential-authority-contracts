use ihat_identity_assertion_contracts::{SignedEvidenceV1, command_digest};
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, EndpointRevocationExecutionCancelFinalizeRequestV1,
    EndpointRevocationExecutionCancellationCleanupV1, ManagementOperationV2,
    SignedAuthorityExchangeV1,
};

pub const ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA: &str = "crowsi://credential-authority/endpoint-revocation-execution-cancel-cleanup-complete-request/v1";
pub const ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_CLEANUP_COMPLETE_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-execution-cancellation-cleanup-complete/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionCancelCleanupCompleteRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub cancel_finalize_request: Box<EndpointRevocationExecutionCancelFinalizeRequestV1>,
    pub cleanup: Box<EndpointRevocationExecutionCancellationCleanupV1>,
    pub acknowledge_exchange: SignedAuthorityExchangeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionCancellationCleanupCompleteV1 {
    pub schema: String,
    pub cleanup_complete_id: String,
    pub cleanup_complete_request_sha256: String,
    pub cleanup_id: String,
    pub cancellation_id: String,
    pub acknowledge_command_digest_sha256: String,
    pub acknowledge_result_digest_sha256: String,
    pub source_device_ref: String,
    pub cleanup_delivery_completed_revision: u64,
    pub cleanup_complete_config_generation: u64,
    pub operation: ManagementOperationV2,
    pub snapshot_revision: u64,
    pub token: SignedEvidenceV1,
    pub issuer: String,
    pub audience: String,
    pub config_generation: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub key_id: String,
    pub signature: String,
}

/// Strictly decodes one terminal cleanup-delivery acknowledgement request.
///
/// # Errors
/// Rejects empty, oversized, open, malformed, or cross-operation documents.
pub fn decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionCancelCleanupCompleteRequestV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value = serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_cancel_cleanup_complete_validation::request(&value)?;
    Ok(value)
}

/// Strictly decodes one signed terminal cleanup-delivery proof.
///
/// # Errors
/// Rejects empty, oversized, open, malformed, or invalid documents.
pub fn decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionCancellationCleanupCompleteV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value = serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_cancel_cleanup_complete_validation::response(&value)?;
    Ok(value)
}

pub(crate) fn acknowledge_command_digest(
    value: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<String, ContractError> {
    command_digest(&value.acknowledge_exchange.request).map_err(|_| ContractError::Invalid)
}
