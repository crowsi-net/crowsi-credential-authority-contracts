/// Verifies a cleanup-complete proof at its durable acceptance time.
///
/// # Errors
/// Rejects a proof that is stale, substituted, malformed, or incorrectly signed.
pub fn verify_endpoint_revocation_execution_cancellation_cleanup_complete_historic(
    value: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    peer: &str,
    trust: &EndpointRevocationExecutionCancellationCleanupCompleteHistoricTrustV1<'_>,
) -> Result<(), ContractError> {
    verify_endpoint_revocation_execution_cancellation_cleanup_complete_at(
        value,
        request,
        cleanup,
        peer,
        &EndpointRevocationExecutionCancellationCleanupCompleteTrustV1 {
            issuer: trust.issuer,
            audience: trust.audience,
            key_id: trust.key_id,
            public_key_hex: trust.public_key_hex,
            minimum_config_generation: trust.minimum_config_generation,
            cleanup_key_id: trust.cleanup_key_id,
            cleanup_public_key_hex: trust.cleanup_public_key_hex,
            minimum_cleanup_config_generation: trust.minimum_cleanup_config_generation,
            acknowledge_key_id: trust.acknowledge_key_id,
            acknowledge_public_key_hex: trust.acknowledge_public_key_hex,
            minimum_acknowledge_config_generation: trust.minimum_acknowledge_config_generation,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: trust.accepted_at_epoch_s,
        },
    )
}

fn exact(
    value: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    peer: &str,
    trust: &EndpointRevocationExecutionCancellationCleanupCompleteTrustV1<'_>,
) -> Result<(), ContractError> {
    let request_digest =
        crate::endpoint_revocation_execution_cancel_cleanup_complete_request_digest(request)?;
    let result_digest =
        crate::endpoint_revocation_cancellation_acknowledgement_result_digest(request)?;
    let command_digest =
        crate::endpoint_revocation_execution_cancel_cleanup_complete::acknowledge_command_digest(
            request,
        )?;
    let valid = value.cleanup_complete_request_sha256 == request_digest
        && value.cleanup_id == cleanup.cleanup_id
        && value.cancellation_id == cleanup.cancellation_id
        && value.acknowledge_command_digest_sha256 == command_digest
        && value.acknowledge_result_digest_sha256 == result_digest
        && value.source_device_ref == peer
        && value.source_device_ref == cleanup.source_device_ref
        && value.cleanup_delivery_completed_revision > cleanup.cleanup_completed_revision
        && value.cleanup_complete_config_generation == cleanup.cleanup_config_generation
        && value.cleanup_complete_config_generation >= trust.minimum_cleanup_config_generation
        && value.operation == cleanup.operation
        && value.token.issued_at_epoch_s >= cleanup.token.issued_at_epoch_s
        && value.token.issued_at_epoch_s <= trust.now_epoch_s
        && value.issuer == trust.issuer
        && value.audience == trust.audience
        && value.key_id == trust.key_id
        && value.config_generation >= trust.minimum_config_generation
        && value.token.key_id == trust.cleanup_key_id
        && value.token.key_id == cleanup.token.key_id
        && value.snapshot_revision >= trust.minimum_snapshot_revision
        && value.snapshot_revision >= value.cleanup_delivery_completed_revision
        && value.issued_at_epoch_s <= trust.now_epoch_s
        && trust.now_epoch_s < value.expires_at_epoch_s;
    valid.then_some(()).ok_or(ContractError::Invalid)
}

fn verify_root_tokens(
    value: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    trust: &EndpointRevocationExecutionCancellationCleanupCompleteTrustV1<'_>,
) -> Result<(), ContractError> {
    for (token, role, proof_id, binding) in [
        (
            &request.cleanup.token,
            VerificationRole::RevocationCancellationCleanup,
            request.cleanup.cleanup_id.as_str(),
            request.cleanup.token.binding_sha256.as_str(),
        ),
        (
            &value.token,
            VerificationRole::RevocationCancellationCleanupComplete,
            value.cleanup_complete_id.as_str(),
            value.cleanup_complete_request_sha256.as_str(),
        ),
    ] {
        ihat_identity_assertion_contracts::verify_signed_evidence_historic(
            token,
            &SignedEvidenceBinding {
                role,
                proof_id,
                binding_sha256: binding,
            },
            trust.cleanup_key_id,
            trust.cleanup_public_key_hex,
        )
        .map_err(|_| ContractError::Invalid)?;
    }
    Ok(())
}
