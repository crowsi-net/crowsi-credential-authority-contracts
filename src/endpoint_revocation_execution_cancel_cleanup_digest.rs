use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ContractError, EndpointRevocationExecutionCancellationCleanupV1};

const CLEANUP_DOMAIN: &[u8] = b"CROWSI-REVOCATION-CANCELLATION-CLEANUP-ID-V1\0";

/// Returns the immutable root-token cleanup identifier.
///
/// # Errors
/// Rejects non-canonical stable claims.
pub fn endpoint_revocation_execution_cancellation_cleanup_id(
    value: &EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<String, ContractError> {
    let stable = Stable {
        schema: &value.schema,
        cancel_finalize_request_sha256: &value.cancel_finalize_request_sha256,
        cancellation_id: &value.cancellation_id,
        cancel_pending_command_digest_sha256: &value.cancel_pending_command_digest_sha256,
        cancel_pending_response_digest_sha256: &value.cancel_pending_response_digest_sha256,
        source_device_ref: &value.source_device_ref,
        cleanup_completed_revision: value.cleanup_completed_revision,
        cleanup_config_generation: value.cleanup_config_generation,
        operation: &value.operation,
        acknowledge_request: &value.acknowledge_request,
        issuer: &value.issuer,
        audience: &value.audience,
    };
    let json = serde_json::to_value(stable).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(CLEANUP_DOMAIN, &json)?,
    )))
}

#[derive(Serialize)]
struct Stable<'a> {
    schema: &'a str,
    cancel_finalize_request_sha256: &'a str,
    cancellation_id: &'a str,
    cancel_pending_command_digest_sha256: &'a str,
    cancel_pending_response_digest_sha256: &'a str,
    source_device_ref: &'a str,
    cleanup_completed_revision: u64,
    cleanup_config_generation: u64,
    operation: &'a crate::ManagementOperationV2,
    acknowledge_request: &'a ihat_identity_assertion_contracts::AuthorityRequestV1,
    issuer: &'a str,
    audience: &'a str,
}
