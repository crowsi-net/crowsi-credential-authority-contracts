use crate::{
    ContractError, EndpointRevocationExecutionReservationHistoricTrustV1,
    EndpointRevocationExecutionReservationV1, EndpointRevocationExecutionReserveRequestV1,
    SignedAuthorityExchangeV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointReservedRevocationFinalResponseTrustV1<'a> {
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub now_epoch_s: u64,
}

/// Verifies a reserved Final result after the Begin and response wrapper have expired.
///
/// The reservation is revalidated at its durable acceptance time under both pinned central trust
/// and the immutable reservation root. The Final response remains bound to the Begin response key,
/// but its current-time expiry is intentionally not applied after execution became irreversible.
///
/// # Errors
/// Rejects a substituted reserve request, token, finalizer, command, Begin, result, response key,
/// generation, future response, or invalid signature.
pub fn verify_endpoint_reserved_revocation_final_exchange_historic_at(
    value: &SignedAuthorityExchangeV1,
    reserve_request: &EndpointRevocationExecutionReserveRequestV1,
    reservation: &EndpointRevocationExecutionReservationV1,
    expected_finalizer_device_ref: &str,
    reservation_trust: &EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
    response_trust: &EndpointReservedRevocationFinalResponseTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::verify_endpoint_revocation_execution_reservation_historic(
        reservation,
        reserve_request,
        expected_finalizer_device_ref,
        reservation_trust,
    )?;
    let expected = crate::attach_revocation_execution_reservation(
        &reserve_request.final_revoke_request,
        reservation,
    )?;
    if value.request != expected
        || reserve_request.begin_exchange.response.key_id != response_trust.key_id
        || value.response.key_id != response_trust.key_id
        || value.response.config_generation < response_trust.minimum_config_generation
        || value.response.issued_at_epoch_s < reservation.issued_at_epoch_s
        || value.response.issued_at_epoch_s < reservation.token.issued_at_epoch_s
        || value.response.issued_at_epoch_s > response_trust.now_epoch_s
    {
        return Err(ContractError::Invalid);
    }
    crate::validate_revocation_final_exchange_against_begin(
        &reserve_request.prepared,
        &reserve_request.begin_exchange,
        value,
    )?;
    crate::verify_authority_exchange_historic(
        value,
        value.request.command.type_name(),
        response_trust.minimum_config_generation,
        response_trust.key_id,
        response_trust.public_key_hex,
    )
}
