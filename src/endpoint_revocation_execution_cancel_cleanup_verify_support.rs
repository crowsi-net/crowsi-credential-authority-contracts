/// Verifies a cancellation-cleanup proof at its durable acceptance time.
///
/// # Errors
/// Rejects a proof that is stale, substituted, malformed, or incorrectly signed.
pub fn verify_endpoint_revocation_execution_cancellation_cleanup_historic(
    value: &EndpointRevocationExecutionCancellationCleanupV1,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cancellation: &EndpointRevocationExecutionCancellationV1,
    peer: &str,
    trust: &EndpointRevocationExecutionCancellationCleanupHistoricTrustV1<'_>,
) -> Result<(), ContractError> {
    verify_endpoint_revocation_execution_cancellation_cleanup_at(
        value,
        request,
        cancellation,
        peer,
        &EndpointRevocationExecutionCancellationCleanupTrustV1 {
            issuer: trust.issuer,
            audience: trust.audience,
            key_id: trust.key_id,
            public_key_hex: trust.public_key_hex,
            minimum_config_generation: trust.minimum_config_generation,
            cleanup_key_id: trust.cleanup_key_id,
            cleanup_public_key_hex: trust.cleanup_public_key_hex,
            minimum_cleanup_config_generation: trust.minimum_cleanup_config_generation,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: trust.accepted_at_epoch_s,
        },
    )
}

fn exact(
    value: &EndpointRevocationExecutionCancellationCleanupV1,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cancellation: &EndpointRevocationExecutionCancellationV1,
    peer: &str,
    trust: &EndpointRevocationExecutionCancellationCleanupTrustV1<'_>,
) -> Result<(), ContractError> {
    let request_digest =
        crate::endpoint_revocation_execution_cancel_finalize_request_digest(request)?;
    let response_digest =
        crate::endpoint_signed_authority_exchange_digest(&request.cancel_pending_exchange)?;
    let command_digest = command_digest(&request.cancel_pending_exchange.request)
        .map_err(|_| ContractError::Invalid)?;
    let valid = value.cancel_finalize_request_sha256 == request_digest
        && value.cancellation_id == cancellation.cancellation_id
        && value.cancel_pending_command_digest_sha256 == command_digest
        && value.cancel_pending_response_digest_sha256 == response_digest
        && value.source_device_ref == peer
        && value.source_device_ref == cancellation.source_device_ref
        && value.cleanup_completed_revision > cancellation.cancellation_accepted_revision
        && value.cleanup_config_generation >= trust.minimum_cleanup_config_generation
        && value.operation == cancellation.operation
        && value.token.issued_at_epoch_s
            >= request.cancel_pending_exchange.response.issued_at_epoch_s
        && value.token.issued_at_epoch_s <= trust.now_epoch_s
        && value.issuer == trust.issuer
        && value.audience == trust.audience
        && value.key_id == trust.key_id
        && value.config_generation >= trust.minimum_config_generation
        && value.token.key_id == trust.cleanup_key_id
        && value.snapshot_revision >= trust.minimum_snapshot_revision
        && value.snapshot_revision >= value.cleanup_completed_revision
        && value.issued_at_epoch_s <= trust.now_epoch_s
        && trust.now_epoch_s < value.expires_at_epoch_s;
    valid.then_some(()).ok_or(ContractError::Invalid)
}
