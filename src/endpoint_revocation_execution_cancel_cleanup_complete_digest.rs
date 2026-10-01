use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    EndpointRevocationExecutionCancellationCleanupCompleteV1,
};

const REQUEST_DOMAIN: &[u8] =
    b"CROWSI-ENDPOINT-REVOCATION-EXECUTION-CANCEL-CLEANUP-COMPLETE-REQUEST-V1\0";
const RESULT_DOMAIN: &[u8] = b"CROWSI-REVOCATION-CANCELLATION-ACKNOWLEDGEMENT-RESULT-V1\0";
const PROOF_DOMAIN: &[u8] = b"CROWSI-REVOCATION-CANCELLATION-CLEANUP-COMPLETE-ID-V1\0";

/// Returns the stable typed cleanup-delivery request digest.
///
/// The iHAT response key, time window, generation, and signature are intentionally excluded so an
/// exact acknowledgement command/result can be freshly re-signed after key rotation.
///
/// # Errors
/// Rejects an invalid or non-canonical request.
pub fn endpoint_revocation_execution_cancel_cleanup_complete_request_digest(
    value: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<String, ContractError> {
    crate::endpoint_revocation_execution_cancel_cleanup_complete_validation::request(value)?;
    let stable = StableRequest {
        schema: &value.schema,
        request_id: &value.request_id,
        operation_id: &value.operation_id,
        cancel_finalize_request: &value.cancel_finalize_request,
        cleanup: StableCleanup {
            schema: &value.cleanup.schema,
            cleanup_id: &value.cleanup.cleanup_id,
            cancel_finalize_request_sha256: &value.cleanup.cancel_finalize_request_sha256,
            cancellation_id: &value.cleanup.cancellation_id,
            cancel_pending_command_digest_sha256: &value
                .cleanup
                .cancel_pending_command_digest_sha256,
            cancel_pending_response_digest_sha256: &value
                .cleanup
                .cancel_pending_response_digest_sha256,
            source_device_ref: &value.cleanup.source_device_ref,
            cleanup_completed_revision: value.cleanup.cleanup_completed_revision,
            cleanup_config_generation: value.cleanup.cleanup_config_generation,
            operation: &value.cleanup.operation,
            acknowledge_request: &value.cleanup.acknowledge_request,
            token: &value.cleanup.token,
            issuer: &value.cleanup.issuer,
            audience: &value.cleanup.audience,
        },
        acknowledge_request: &value.acknowledge_exchange.request,
        acknowledge_outcome: &value.acknowledge_exchange.response.outcome,
    };
    let json = serde_json::to_value(stable).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(REQUEST_DOMAIN, &json)?,
    )))
}

/// Returns the stable exact iHAT acknowledgement command/result digest.
///
/// # Errors
/// Rejects a structurally invalid delivery request or non-canonical outcome.
pub fn endpoint_revocation_cancellation_acknowledgement_result_digest(
    value: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<String, ContractError> {
    crate::endpoint_revocation_execution_cancel_cleanup_complete_validation::request(value)?;
    let stable = Acknowledgement {
        request: &value.acknowledge_exchange.request,
        outcome: &value.acknowledge_exchange.response.outcome,
    };
    let json = serde_json::to_value(stable).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(RESULT_DOMAIN, &json)?,
    )))
}

/// Returns the immutable root-token cleanup-delivery identifier.
///
/// # Errors
/// Rejects non-canonical stable claims.
pub fn endpoint_revocation_execution_cancellation_cleanup_complete_id(
    value: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
) -> Result<String, ContractError> {
    let stable = Stable {
        schema: &value.schema,
        request_sha256: &value.cleanup_complete_request_sha256,
        cleanup_id: &value.cleanup_id,
        cancellation_id: &value.cancellation_id,
        command_sha256: &value.acknowledge_command_digest_sha256,
        result_sha256: &value.acknowledge_result_digest_sha256,
        source_device_ref: &value.source_device_ref,
        completed_revision: value.cleanup_delivery_completed_revision,
        root_generation: value.cleanup_complete_config_generation,
        operation: &value.operation,
        issuer: &value.issuer,
        audience: &value.audience,
    };
    let json = serde_json::to_value(stable).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(PROOF_DOMAIN, &json)?,
    )))
}

#[derive(Serialize)]
struct Stable<'a> {
    schema: &'a str,
    request_sha256: &'a str,
    cleanup_id: &'a str,
    cancellation_id: &'a str,
    command_sha256: &'a str,
    result_sha256: &'a str,
    source_device_ref: &'a str,
    completed_revision: u64,
    root_generation: u64,
    operation: &'a crate::ManagementOperationV2,
    issuer: &'a str,
    audience: &'a str,
}

include!("endpoint_revocation_execution_cancel_cleanup_complete_digest_types.rs");
