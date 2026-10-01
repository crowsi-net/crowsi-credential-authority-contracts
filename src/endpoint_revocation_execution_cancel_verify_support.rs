fn exact(
    value: &EndpointRevocationExecutionCancellationV1,
    request: &EndpointRevocationExecutionCancelRequestV1,
    peer: &str,
    trust: &EndpointRevocationExecutionCancellationTrustV1<'_>,
) -> Result<(), ContractError> {
    let (identity, identity_response_issued_at) = match &request.cancel_envelope.evidence {
        crate::EndpointManagementEvidenceV2::Cancel {
            identity_exchange, ..
        } => (
            crate::identity_evidence_from_exchange(identity_exchange)?,
            identity_exchange.response.issued_at_epoch_s,
        ),
        _ => return Err(ContractError::Invalid),
    };
    let begun = crate::endpoint_revocation_begin::validate(
        &request.prepared,
        &request.begin_exchange,
        None,
    )?;
    let AuthorityCommand::CancelPendingRevocation(command) = &value.cancel_pending_request.command
    else {
        return Err(ContractError::Invalid);
    };
    let valid = value.cancellation_request_sha256
        == crate::endpoint_revocation_execution_cancel_request_digest(request)?
        && value.cancel_envelope_digest_sha256
            == crate::endpoint_revocation_cancel_envelope_digest(&request.cancel_envelope)?
        && value.pre_final_acceptance_request_sha256 == request.pre_final_acceptance_request_sha256
        && value.prepared_operation_digest_sha256
            == crate::endpoint_operation_digest(&request.prepared)?
        && value.opaque_owner_ref == request.prepared.opaque_owner_ref
        && value.service_id == identity.assertion.service_id
        && value.pairwise_subject == identity.assertion.pairwise_subject
        && value.source_device_ref == identity.assertion.device_id
        && value.source_device_ref == request.prepared.source_device_ref
        && value.source_device_ref == peer
        && value.source_session_ref == identity.assertion.session_ref
        && value.source_session_ref == request.prepared.source_session_ref
        && value.target_digest_sha256 == begun.target_digest
        && value.begin_exchange_digest_sha256
            == crate::endpoint_signed_authority_exchange_digest(&request.begin_exchange)?
        && value.begin_command_digest_sha256
            == ihat_identity_assertion_contracts::command_digest(&request.begin_exchange.request)
                .map_err(|_| ContractError::Invalid)?
        && value.finalize_command_id == request.operation_id
        && value.cancelled_state_revision == request.expected_cancelled_state_revision
        && value.execution_reservation_id.is_none()
        && command.command_id == request.request_id
        && value.cancel_pending_request.request_id == request.request_id
        && value.token.issued_at_epoch_s >= identity_response_issued_at
        && value.token.issued_at_epoch_s <= trust.now_epoch_s
        && value.issuer == trust.issuer
        && value.audience == trust.audience
        && value.key_id == trust.key_id
        && value.config_generation >= trust.minimum_config_generation
        && value.cancellation_config_generation >= trust.minimum_cancellation_config_generation
        && value.token.key_id == trust.cancellation_key_id
        && value.snapshot_revision >= trust.minimum_snapshot_revision
        && value.issued_at_epoch_s <= trust.now_epoch_s
        && trust.now_epoch_s < value.expires_at_epoch_s
        && crate::endpoint_prepared_lookup_binding::operation_prepared(
            &value.operation,
            &request.prepared,
        );
    valid.then_some(()).ok_or(ContractError::Invalid)
}
