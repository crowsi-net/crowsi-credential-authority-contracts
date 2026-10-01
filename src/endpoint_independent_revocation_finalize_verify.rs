use crate::{
    ContractError, EndpointIndependentRevocationFinalizeRequestV1,
    EndpointRevocationExecutionReservationV1, ManagementOperationState, ManagementProjectionBodyV2,
    ManagementProjectionV2,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIndependentRevocationFinalizeProjectionTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

/// Correlates Final with the exact partial ceremony and irreversible central reservation.
///
/// # Errors
/// Rejects Begin, Approval, token, reservation, actor, or Final substitution.
pub fn validate_endpoint_independent_revocation_finalize_against_acceptance(
    value: &EndpointIndependentRevocationFinalizeRequestV1,
    stored_pre_final: &crate::EndpointIndependentRevocationPreFinalRequestV1,
    stored_reserve: &crate::EndpointRevocationExecutionReserveRequestV1,
    reservation: &EndpointRevocationExecutionReservationV1,
) -> Result<(), ContractError> {
    crate::endpoint_independent_revocation_finalize_validation::validate(value)?;
    crate::endpoint_independent_revocation_pre_final_validation::validate(stored_pre_final)?;
    crate::endpoint_revocation_execution_reserve_validation::request(stored_reserve)?;
    crate::endpoint_revocation_execution_reserve_validation::reservation(reservation)?;
    let final_request = crate::attach_revocation_execution_reservation(
        &stored_reserve.final_revoke_request,
        reservation,
    )?;
    let exact = value.approve_revocation_request == stored_pre_final.approve_revocation_request
        && value.prepared == stored_pre_final.prepared
        && value.pre_final_request_sha256
            == crate::endpoint_independent_revocation_pre_final_request_digest(stored_pre_final)?
        && value.accepted_identity_exchange == stored_pre_final.accepted_identity_exchange
        && value.begin_exchange == stored_pre_final.revocation_ceremony.begin
        && value.approval_exchange == stored_pre_final.revocation_ceremony.approval
        && stored_reserve.original_request == value.approve_revocation_request
        && stored_reserve.prepared == value.prepared
        && stored_reserve.pre_final_acceptance_request_sha256 == value.pre_final_request_sha256
        && stored_reserve.accepted_identity_exchange == value.accepted_identity_exchange
        && stored_reserve.begin_exchange == value.begin_exchange
        && stored_reserve.approval_exchange.as_ref() == Some(&value.approval_exchange)
        && stored_reserve.reconcile_digest == value.reconcile_digest
        && reservation.reservation_request_sha256
            == crate::endpoint_revocation_execution_reserve_request_digest(stored_reserve)?
        && value.execution_reservation_id == reservation.reservation_id
        && value.execution_reservation_token == reservation.token
        && value.final_revoke_exchange.request == final_request
        && reservation.reconcile_digest == value.reconcile_digest
        && reservation.finalizer_device_ref
            == crate::identity_evidence_from_exchange(&value.accepted_identity_exchange)?
                .assertion
                .device_id
        && reservation.pre_final_state_revision == value.pre_final_state_revision
        && reservation.reserved_state_revision == value.expected_state_revision;
    exact.then_some(()).ok_or(ContractError::Invalid)
}

/// Verifies the fresh central projection returned by independent revocation finalization.
///
/// # Errors
/// Rejects cross-request, cross-peer, cross-owner, stale, malformed, or unsigned output.
pub fn verify_endpoint_independent_revocation_finalize_projection_at(
    value: &ManagementProjectionV2,
    request: &EndpointIndependentRevocationFinalizeRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointIndependentRevocationFinalizeProjectionTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_independent_revocation_finalize_validation::validate(request)?;
    crate::management_validation::projection(value)?;
    let ManagementProjectionBodyV2::Operation { operation } = &value.body else {
        return Err(ContractError::Invalid);
    };
    let identity = crate::identity_evidence_from_exchange(&request.accepted_identity_exchange)?;
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let unknown = request
        .expected_state_revision
        .checked_add(1)
        .ok_or(ContractError::Invalid)?;
    let completed = request
        .expected_state_revision
        .checked_add(2)
        .ok_or(ContractError::Invalid)?;
    let state = operation.state == ManagementOperationState::Unknown
        && operation.state_revision >= unknown
        && operation.reconcile_digest.as_deref() == Some(&request.reconcile_digest)
        || operation.state == ManagementOperationState::Completed
            && operation.state_revision >= completed;
    let exact = value.request_id == request.approve_revocation_request.request_id
        && value.command_digest_sha256
            == crate::management_command_digest(&request.approve_revocation_request)?
        && value.issuer == trust.issuer
        && value.audience == trust.audience
        && value.service_id == assertion.service_id
        && value.pairwise_subject == assertion.pairwise_subject
        && value.opaque_account_ref == request.prepared.opaque_owner_ref
        && value.current_device_ref == assertion.device_id
        && value.current_device_ref == expected_peer_device_ref
        && value.current_session_ref == assertion.session_ref
        && value.subject_revocation_epoch == epochs.subject
        && value.service_revocation_epoch == epochs.service
        && value.device_revocation_epoch == epochs.device
        && value.session_revocation_epoch == epochs.session
        && value.device_posture_state == assertion.device_posture.state
        && value.device_posture_revision == assertion.device_posture.revision
        && value.device_proof_key_ref == assertion.device_proof_key_ref
        && value.snapshot_revision >= trust.minimum_snapshot_revision
        && value.key_id == trust.key_id
        && value.issued_at_epoch_s <= trust.now_epoch_s
        && trust.now_epoch_s < value.expires_at_epoch_s
        && operation.operation_id == request.operation_id
        && state
        && crate::endpoint_prepared_lookup_binding::operation_prepared(
            operation,
            &request.prepared,
        );
    if !exact {
        return Err(ContractError::Invalid);
    }
    crate::management_crypto::verify(
        trust.public_key_hex,
        &value.signature,
        &crate::canonical_management_projection(value)?,
    )
}
