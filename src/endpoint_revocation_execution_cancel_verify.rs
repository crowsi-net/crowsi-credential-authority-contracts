use ihat_identity_assertion_contracts::{
    AuthorityCommand, SignedEvidenceBinding, VerificationRole,
};

use crate::{
    ContractError, EndpointRevocationExecutionCancelRequestV1,
    EndpointRevocationExecutionCancellationV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionCancellationTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub cancellation_key_id: &'a str,
    pub cancellation_public_key_hex: &'a str,
    pub minimum_cancellation_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionCancellationHistoricTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub cancellation_key_id: &'a str,
    pub cancellation_public_key_hex: &'a str,
    pub minimum_cancellation_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub accepted_at_epoch_s: u64,
}

/// Verifies one exact terminal Cancel cleanup token and its fresh signed outer response.
///
/// # Errors
/// Rejects peer, operation, pre-final, Begin, reservation-absence, token, or signature drift.
pub fn verify_endpoint_revocation_execution_cancellation_at(
    value: &EndpointRevocationExecutionCancellationV1,
    request: &EndpointRevocationExecutionCancelRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationExecutionCancellationTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_validation::request(request)?;
    crate::endpoint_revocation_execution_cancel_validation::cancellation(value)?;
    exact(value, request, expected_peer_device_ref, trust)?;
    ihat_identity_assertion_contracts::verify_signed_evidence_historic(
        &value.token,
        &SignedEvidenceBinding {
            role: VerificationRole::RevocationExecutionCancellation,
            proof_id: &value.cancellation_id,
            binding_sha256: &value.token.binding_sha256,
        },
        trust.cancellation_key_id,
        trust.cancellation_public_key_hex,
    )
    .map_err(|_| ContractError::Invalid)?;
    crate::management_crypto::verify(
        trust.public_key_hex,
        &value.signature,
        &crate::canonical_endpoint_revocation_execution_cancellation(value)?,
    )
}

/// Revalidates a stored cancellation under its pinned acceptance-time trust.
///
/// # Errors
/// Rejects a response that was not live, exact, and signed when durably accepted.
pub fn verify_endpoint_revocation_execution_cancellation_historic(
    value: &EndpointRevocationExecutionCancellationV1,
    request: &EndpointRevocationExecutionCancelRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationExecutionCancellationHistoricTrustV1<'_>,
) -> Result<(), ContractError> {
    verify_endpoint_revocation_execution_cancellation_at(
        value,
        request,
        expected_peer_device_ref,
        &EndpointRevocationExecutionCancellationTrustV1 {
            issuer: trust.issuer,
            audience: trust.audience,
            key_id: trust.key_id,
            public_key_hex: trust.public_key_hex,
            minimum_config_generation: trust.minimum_config_generation,
            cancellation_key_id: trust.cancellation_key_id,
            cancellation_public_key_hex: trust.cancellation_public_key_hex,
            minimum_cancellation_config_generation: trust.minimum_cancellation_config_generation,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: trust.accepted_at_epoch_s,
        },
    )
}

include!("endpoint_revocation_execution_cancel_verify_support.rs");
