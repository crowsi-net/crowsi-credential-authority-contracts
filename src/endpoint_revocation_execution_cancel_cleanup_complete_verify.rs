use ihat_identity_assertion_contracts::{SignedEvidenceBinding, VerificationRole};

use crate::{
    ContractError, EndpointRevocationCancellationCleanupResponseTrustV1,
    EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    EndpointRevocationExecutionCancellationCleanupCompleteV1,
    EndpointRevocationExecutionCancellationCleanupV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionCancellationCleanupCompleteTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub cleanup_key_id: &'a str,
    pub cleanup_public_key_hex: &'a str,
    pub minimum_cleanup_config_generation: u64,
    pub acknowledge_key_id: &'a str,
    pub acknowledge_public_key_hex: &'a str,
    pub minimum_acknowledge_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionCancellationCleanupCompleteHistoricTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub cleanup_key_id: &'a str,
    pub cleanup_public_key_hex: &'a str,
    pub minimum_cleanup_config_generation: u64,
    pub acknowledge_key_id: &'a str,
    pub acknowledge_public_key_hex: &'a str,
    pub minimum_acknowledge_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub accepted_at_epoch_s: u64,
}

/// Correlates the terminal delivery request with E and the exact iHAT acknowledgement.
///
/// # Errors
/// Rejects cleanup, operation, request, command, result, or exchange substitution.
pub fn validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance(
    value: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_cleanup_complete_validation::request(value)?;
    let valid = value.cleanup.cleanup_id == cleanup.cleanup_id
        && value.cleanup.token == cleanup.token
        && value.operation_id == cleanup.operation.operation_id
        && value.cancel_finalize_request.operation_id == cleanup.operation.operation_id;
    valid.then_some(()).ok_or(ContractError::Invalid)
}

/// Verifies a fresh central terminal cleanup-delivery proof.
///
/// # Errors
/// Rejects peer, root token, iHAT acknowledgement, revision, or outer signature drift.
pub fn verify_endpoint_revocation_execution_cancellation_cleanup_complete_at(
    value: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationExecutionCancellationCleanupCompleteTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_cleanup_complete_validation::response(value)?;
    validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance(
        request, cleanup,
    )?;
    exact(value, request, cleanup, expected_peer_device_ref, trust)?;
    verify_root_tokens(value, request, trust)?;
    crate::verify_endpoint_revocation_cancellation_cleanup_exchange_historic_at(
        &request.acknowledge_exchange,
        cleanup,
        &EndpointRevocationCancellationCleanupResponseTrustV1 {
            key_id: trust.acknowledge_key_id,
            public_key_hex: trust.acknowledge_public_key_hex,
            minimum_config_generation: trust.minimum_acknowledge_config_generation,
            now_epoch_s: trust.now_epoch_s,
        },
    )?;
    crate::management_crypto::verify(
        trust.public_key_hex,
        &value.signature,
        &crate::canonical_endpoint_revocation_execution_cancellation_cleanup_complete(value)?,
    )
}

include!("endpoint_revocation_execution_cancel_cleanup_complete_verify_support.rs");
