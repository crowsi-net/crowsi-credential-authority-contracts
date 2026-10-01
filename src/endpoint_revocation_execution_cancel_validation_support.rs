fn token(value: &EndpointRevocationExecutionCancellationV1) -> bool {
    value.token.schema == SIGNED_EVIDENCE_SCHEMA
        && value.token.role == VerificationRole::RevocationExecutionCancellation
        && value.token.proof_id == value.cancellation_id
        && value.token.key_id.as_str()
            == match &value.cancel_pending_request.command {
                AuthorityCommand::CancelPendingRevocation(command) => command.authority_id.as_str(),
                _ => return false,
            }
        && value.token.binding_sha256
            == command_digest(&value.cancel_pending_request).unwrap_or_default()
        && id(&value.token.key_id, 128)
        && lower_hex(&value.token.signature, 64)
}

fn cancel_command(value: &EndpointRevocationExecutionCancellationV1) -> bool {
    let Ok(wire) = serde_json::to_vec(&value.cancel_pending_request) else {
        return false;
    };
    if !value.cancel_pending_request.evidence.is_empty()
        || ihat_identity_assertion_contracts::decode_authority_request_strict(&wire).is_err()
    {
        return false;
    }
    let AuthorityCommand::CancelPendingRevocation(command) = &value.cancel_pending_request.command
    else {
        return false;
    };
    command.finalize_command_id == value.finalize_command_id
        && command.opaque_owner_ref == value.opaque_owner_ref
        && command.service_id == value.service_id
        && command.pairwise_subject == value.pairwise_subject
        && command.source_device_id == value.source_device_ref
        && command.source_session_ref == value.source_session_ref
        && command.target_digest_sha256 == value.target_digest_sha256
        && command.begin_command_digest_sha256 == value.begin_command_digest_sha256
        && command.cancelled_state_revision == value.cancelled_state_revision
        && matches!(value.cancel_pending_request.evidence.as_slice(), [])
}
