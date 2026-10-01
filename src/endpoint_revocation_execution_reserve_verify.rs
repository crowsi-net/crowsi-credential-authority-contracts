use ihat_identity_assertion_contracts::{SignedEvidenceBinding, VerificationRole, command_digest};

use crate::{
    ContractError, EndpointRevocationExecutionReservationV1,
    EndpointRevocationExecutionReserveRequestV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionReservationTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub reservation_key_id: &'a str,
    pub reservation_public_key_hex: &'a str,
    pub minimum_reservation_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionReservationHistoricTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub reservation_key_id: &'a str,
    pub reservation_public_key_hex: &'a str,
    pub minimum_reservation_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub accepted_at_epoch_s: u64,
}

/// Verifies the immutable token and fresh outer response for one exact reserve request.
///
/// # Errors
/// Rejects request, actor, prepared, command, generation, time, token, or signature substitution.
pub fn verify_endpoint_revocation_execution_reservation_at(
    value: &EndpointRevocationExecutionReservationV1,
    request: &EndpointRevocationExecutionReserveRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationExecutionReservationTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_reserve_validation::request(request)?;
    crate::endpoint_revocation_execution_reserve_validation::reservation(value)?;
    exact(value, request, expected_peer_device_ref, trust)?;
    let token = &value.token;
    ihat_identity_assertion_contracts::verify_signed_evidence_historic(
        token,
        &SignedEvidenceBinding {
            role: VerificationRole::RevocationExecutionReservation,
            proof_id: &value.reservation_id,
            binding_sha256: &value.final_command_digest_sha256,
        },
        trust.reservation_key_id,
        trust.reservation_public_key_hex,
    )
    .map_err(|_| ContractError::Invalid)?;
    crate::management_crypto::verify(
        trust.public_key_hex,
        &value.signature,
        &crate::canonical_endpoint_revocation_execution_reservation(value)?,
    )
}

/// Revalidates a stored reservation using its pinned outer key and acceptance time.
///
/// The immutable execution token is always verified with the non-rotating reservation root.
///
/// # Errors
/// Rejects a reservation that was not live, exact, and correctly signed when accepted.
pub fn verify_endpoint_revocation_execution_reservation_historic(
    value: &EndpointRevocationExecutionReservationV1,
    request: &EndpointRevocationExecutionReserveRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
) -> Result<(), ContractError> {
    verify_endpoint_revocation_execution_reservation_at(
        value,
        request,
        expected_peer_device_ref,
        &EndpointRevocationExecutionReservationTrustV1 {
            issuer: trust.issuer,
            audience: trust.audience,
            key_id: trust.key_id,
            public_key_hex: trust.public_key_hex,
            minimum_config_generation: trust.minimum_config_generation,
            reservation_key_id: trust.reservation_key_id,
            reservation_public_key_hex: trust.reservation_public_key_hex,
            minimum_reservation_config_generation: trust.minimum_reservation_config_generation,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: trust.accepted_at_epoch_s,
        },
    )
}

fn exact(
    value: &EndpointRevocationExecutionReservationV1,
    request: &EndpointRevocationExecutionReserveRequestV1,
    peer: &str,
    trust: &EndpointRevocationExecutionReservationTrustV1<'_>,
) -> Result<(), ContractError> {
    let identity = crate::identity_evidence_from_exchange(&request.accepted_identity_exchange)?;
    let begun = begin_metadata(&request.begin_exchange)?;
    let approval = request
        .approval_exchange
        .as_ref()
        .map(crate::endpoint_signed_authority_exchange_digest)
        .transpose()?;
    let valid = value.reservation_request_sha256
        == crate::endpoint_revocation_execution_reserve_request_digest(request)?
        && value.original_request_id == request.original_request.request_id
        && value.original_command_digest_sha256
            == crate::management_command_digest(&request.original_request)?
        && value.prepared_operation_digest_sha256
            == crate::endpoint_operation_digest(&request.prepared)?
        && value.reconcile_digest == request.reconcile_digest
        && value.opaque_owner_ref == request.prepared.opaque_owner_ref
        && value.service_id == identity.assertion.service_id
        && value.pairwise_subject == identity.assertion.pairwise_subject
        && value.source_device_ref == request.prepared.source_device_ref
        && value.finalizer_device_ref == identity.assertion.device_id
        && value.finalizer_device_ref == peer
        && value.target_digest_sha256 == begun.target_digest
        && value.begin_exchange_digest_sha256
            == crate::endpoint_signed_authority_exchange_digest(&request.begin_exchange)?
        && value.approval_exchange_digest_sha256 == approval
        && value.final_command_digest_sha256
            == command_digest(&request.final_revoke_request).map_err(|_| ContractError::Invalid)?
        && value.token.issued_at_epoch_s < begun.expires_at_epoch_s
        && value.token.issued_at_epoch_s
            >= request
                .reservation_identity_exchange
                .response
                .issued_at_epoch_s
        && request
            .approval_exchange
            .as_ref()
            .is_none_or(|item| value.token.issued_at_epoch_s >= item.response.issued_at_epoch_s);
    (valid && response_context(value, request, trust))
        .then_some(())
        .ok_or(ContractError::Invalid)
}

include!("endpoint_revocation_execution_reserve_verify_support.rs");
