use ihat_identity_assertion_contracts::{AuthorityEvidence, AuthorityRequestV1, command_digest};

use crate::{ContractError, EndpointRevocationExecutionReservationV1};

/// Adds the exact central execution token to a previously reserved evidence-free Final request.
///
/// The authority command digest excludes evidence, so the reservation binding remains exact.
///
/// # Errors
/// Rejects a request that already carries evidence or does not match the signed token binding.
pub fn attach_revocation_execution_reservation(
    value: &AuthorityRequestV1,
    reservation: &EndpointRevocationExecutionReservationV1,
) -> Result<AuthorityRequestV1, ContractError> {
    crate::endpoint_revocation_execution_reserve_validation::reservation(reservation)?;
    let digest = command_digest(value).map_err(|_| ContractError::Invalid)?;
    if !value.evidence.is_empty()
        || digest != reservation.final_command_digest_sha256
        || reservation.token.binding_sha256 != digest
    {
        return Err(ContractError::Invalid);
    }
    let mut result = value.clone();
    result
        .evidence
        .push(AuthorityEvidence::Signed(reservation.token.clone()));
    Ok(result)
}
