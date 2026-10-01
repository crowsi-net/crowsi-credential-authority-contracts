use ihat_identity_assertion_contracts::{SignedEvidenceBinding, VerificationRole, command_digest};

use crate::{
    ContractError, EndpointRevocationExecutionCancelFinalizeRequestV1,
    EndpointRevocationExecutionCancellationCleanupV1, EndpointRevocationExecutionCancellationV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionCancellationCleanupTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub cleanup_key_id: &'a str,
    pub cleanup_public_key_hex: &'a str,
    pub minimum_cleanup_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionCancellationCleanupHistoricTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub cleanup_key_id: &'a str,
    pub cleanup_public_key_hex: &'a str,
    pub minimum_cleanup_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub accepted_at_epoch_s: u64,
}

/// Verifies one fresh central cleanup-completion proof.
///
/// # Errors
/// Rejects acknowledgement, response digest, peer, revision, token, or signature drift.
pub fn verify_endpoint_revocation_execution_cancellation_cleanup_at(
    value: &EndpointRevocationExecutionCancellationCleanupV1,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cancellation: &EndpointRevocationExecutionCancellationV1,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationExecutionCancellationCleanupTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_cleanup_validation::validate(value)?;
    crate::validate_endpoint_revocation_execution_cancel_finalize_against_acceptance(
        request,
        cancellation,
    )?;
    exact(
        value,
        request,
        cancellation,
        expected_peer_device_ref,
        trust,
    )?;
    ihat_identity_assertion_contracts::verify_signed_evidence_historic(
        &request.cancellation.token,
        &SignedEvidenceBinding {
            role: VerificationRole::RevocationExecutionCancellation,
            proof_id: &request.cancellation.cancellation_id,
            binding_sha256: &request.cancellation.token.binding_sha256,
        },
        trust.cleanup_key_id,
        trust.cleanup_public_key_hex,
    )
    .map_err(|_| ContractError::Invalid)?;
    ihat_identity_assertion_contracts::verify_signed_evidence_historic(
        &value.token,
        &SignedEvidenceBinding {
            role: VerificationRole::RevocationCancellationCleanup,
            proof_id: &value.cleanup_id,
            binding_sha256: &value.token.binding_sha256,
        },
        trust.cleanup_key_id,
        trust.cleanup_public_key_hex,
    )
    .map_err(|_| ContractError::Invalid)?;
    crate::management_crypto::verify(
        trust.public_key_hex,
        &value.signature,
        &crate::canonical_endpoint_revocation_execution_cancellation_cleanup(value)?,
    )
}

include!("endpoint_revocation_execution_cancel_cleanup_verify_support.rs");
