use crate::{ContractError, EndpointRevocationFinalizeRequestV1, SignedAuthorityExchangeV1};

/// Correlates self-revocation Final with the exact irreversible execution reservation.
///
/// # Errors
/// Rejects a substituted pre-final request, Begin, token, reservation, or Final request.
pub fn validate_endpoint_revocation_finalize_against_acceptance(
    value: &EndpointRevocationFinalizeRequestV1,
    stored_pre_final_request_sha256: &str,
    stored_begin: &SignedAuthorityExchangeV1,
    stored_reserve: &crate::EndpointRevocationExecutionReserveRequestV1,
    reservation: &crate::EndpointRevocationExecutionReservationV1,
) -> Result<(), ContractError> {
    crate::validate_endpoint_revocation_finalize_against_begin(value, stored_begin)?;
    crate::endpoint_revocation_execution_reserve_validation::request(stored_reserve)?;
    crate::endpoint_revocation_execution_reserve_validation::reservation(reservation)?;
    let final_request = crate::attach_revocation_execution_reservation(
        &stored_reserve.final_revoke_request,
        reservation,
    )?;
    let exact = value.pre_final_request_sha256 == stored_pre_final_request_sha256
        && stored_reserve.pre_final_acceptance_request_sha256 == stored_pre_final_request_sha256
        && stored_reserve.original_request == value.source_approve_request
        && stored_reserve.prepared == value.prepared
        && stored_reserve.accepted_identity_exchange == value.accepted_identity_exchange
        && stored_reserve.begin_exchange == *stored_begin
        && stored_reserve.approval_exchange.is_none()
        && stored_reserve.reconcile_digest == value.reconcile_digest
        && reservation.reservation_request_sha256
            == crate::endpoint_revocation_execution_reserve_request_digest(stored_reserve)?
        && value.execution_reservation_id == reservation.reservation_id
        && value.execution_reservation_token == reservation.token
        && value.final_revoke_exchange.request == final_request
        && value.pre_final_state_revision == reservation.pre_final_state_revision
        && value.expected_state_revision == reservation.reserved_state_revision
        && reservation.finalizer_device_ref == value.prepared.source_device_ref
        && reservation.reconcile_digest == value.reconcile_digest;
    exact.then_some(()).ok_or(ContractError::Invalid)
}
