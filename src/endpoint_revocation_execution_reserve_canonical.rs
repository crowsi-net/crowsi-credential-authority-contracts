use crate::{ContractError, EndpointRevocationExecutionReservationV1};

/// Returns the domain-separated JCS bytes signed around one fresh reservation response.
///
/// # Errors
/// Rejects an invalid or non-object response.
pub fn canonical_endpoint_revocation_execution_reservation(
    value: &EndpointRevocationExecutionReservationV1,
) -> Result<Vec<u8>, ContractError> {
    let mut json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    json.as_object_mut()
        .ok_or(ContractError::Invalid)?
        .remove("signature");
    crate::management_crypto::domain_jcs(
        crate::endpoint_revocation_execution_reserve_digest::RESERVATION_RESPONSE_DOMAIN,
        &json,
    )
}
