use crate::{ContractError, EndpointRevocationExecutionCancellationCleanupCompleteV1};

const RESPONSE_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-REVOCATION-CANCELLATION-CLEANUP-COMPLETE-V1\0";

/// Returns canonical signed cleanup-delivery proof bytes without the signature.
///
/// # Errors
/// Rejects a proof that cannot be represented canonically.
pub fn canonical_endpoint_revocation_execution_cancellation_cleanup_complete(
    value: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
) -> Result<Vec<u8>, ContractError> {
    let mut json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    json.as_object_mut()
        .ok_or(ContractError::Invalid)?
        .remove("signature");
    crate::management_crypto::domain_jcs(RESPONSE_DOMAIN, &json)
}
