use ihat_identity_assertion_contracts::{
    AuthorityCommand, SIGNED_EVIDENCE_SCHEMA, VerificationRole, command_digest,
};

use crate::{
    ContractError, EndpointRevocationExecutionCancellationCleanupV1, ManagementOperationState,
    management_operation_validation::{digest, id, lower_hex, operation_valid, reference},
};

pub(crate) fn validate(
    value: &EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<(), ContractError> {
    let token_lifetime = value
        .token
        .expires_at_epoch_s
        .checked_sub(value.token.issued_at_epoch_s);
    let outer_lifetime = value
        .expires_at_epoch_s
        .checked_sub(value.issued_at_epoch_s);
    let valid = value.schema == crate::ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_CLEANUP_SCHEMA
        && digest(&value.cleanup_id)
        && digest(&value.cancel_finalize_request_sha256)
        && digest(&value.cancellation_id)
        && digest(&value.cancel_pending_command_digest_sha256)
        && digest(&value.cancel_pending_response_digest_sha256)
        && reference(&value.source_device_ref)
        && value.cleanup_completed_revision > 0
        && value.cleanup_config_generation > 0
        && operation_valid(&value.operation)
        && value.operation.state == ManagementOperationState::Cancelled
        && value.snapshot_revision >= value.cleanup_completed_revision
        && value.config_generation == value.cleanup_config_generation
        && value.token.issued_at_epoch_s <= value.issued_at_epoch_s
        && token_lifetime.is_some_and(|item| (1..=120).contains(&item))
        && outer_lifetime.is_some_and(|item| (1..=30).contains(&item))
        && id(&value.issuer, 256)
        && id(&value.audience, 256)
        && id(&value.key_id, 128)
        && lower_hex(&value.signature, 64)
        && token(value)
        && command(value)
        && crate::endpoint_revocation_execution_cancellation_cleanup_id(value)
            .is_ok_and(|item| item == value.cleanup_id);
    valid.then_some(()).ok_or(ContractError::Invalid)
}

fn token(value: &EndpointRevocationExecutionCancellationCleanupV1) -> bool {
    value.token.schema == SIGNED_EVIDENCE_SCHEMA
        && value.token.role == VerificationRole::RevocationCancellationCleanup
        && value.token.proof_id == value.cleanup_id
        && value.token.binding_sha256
            == command_digest(&value.acknowledge_request).unwrap_or_default()
        && id(&value.token.key_id, 128)
        && lower_hex(&value.token.signature, 64)
}

fn command(value: &EndpointRevocationExecutionCancellationCleanupV1) -> bool {
    let Ok(wire) = serde_json::to_vec(&value.acknowledge_request) else {
        return false;
    };
    if !value.acknowledge_request.evidence.is_empty()
        || ihat_identity_assertion_contracts::decode_authority_request_strict(&wire).is_err()
    {
        return false;
    }
    let AuthorityCommand::AcknowledgePendingCancellation(command) =
        &value.acknowledge_request.command
    else {
        return false;
    };
    command.command_id == value.cancel_finalize_request_sha256
        && command.cancellation_id == value.cancellation_id
        && command.cancel_pending_command_digest_sha256
            == value.cancel_pending_command_digest_sha256
        && command.cancel_pending_response_digest_sha256
            == value.cancel_pending_response_digest_sha256
        && command.source_device_id == value.source_device_ref
        && command.cleanup_completed_revision == value.cleanup_completed_revision
        && command.authority_id == value.token.key_id
}
