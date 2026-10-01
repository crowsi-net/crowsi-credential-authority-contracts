use crate::{ContractError, EndpointRevocationExecutionCancellationCleanupV1};

const RESPONSE_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-REVOCATION-CANCELLATION-CLEANUP-V1\0";

/// Returns the canonical signed outer cleanup response without its signature.
///
/// # Errors
/// Rejects a response that cannot be represented canonically.
pub fn canonical_endpoint_revocation_execution_cancellation_cleanup(
    value: &EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<Vec<u8>, ContractError> {
    let mut json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    json.as_object_mut()
        .ok_or(ContractError::Invalid)?
        .remove("signature");
    crate::management_crypto::domain_jcs(RESPONSE_DOMAIN, &json)
}
