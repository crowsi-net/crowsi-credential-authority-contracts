use ihat_identity_assertion_contracts::{SIGNED_EVIDENCE_SCHEMA, VerificationRole};

use crate::{
    ContractError, EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    EndpointRevocationExecutionCancellationCleanupCompleteV1, ManagementOperationState,
    management_operation_validation::{digest, id, lower_hex, operation_valid, reference},
};

pub(crate) fn request(
    value: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_finalize_validation::validate(
        &value.cancel_finalize_request,
    )?;
    crate::endpoint_revocation_execution_cancel_cleanup_validation::validate(&value.cleanup)?;
    crate::validate_endpoint_revocation_cancellation_cleanup_exchange(
        &value.acknowledge_exchange,
        &value.cleanup,
    )?;
    let finalize_digest = crate::endpoint_revocation_execution_cancel_finalize_request_digest(
        &value.cancel_finalize_request,
    )?;
    let valid = value.schema
        == crate::ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA
        && id(&value.request_id, 128)
        && digest(&value.operation_id)
        && value.operation_id == value.cancel_finalize_request.operation_id
        && value.cleanup.cancel_finalize_request_sha256 == finalize_digest
        && value.cleanup.operation == value.cancel_finalize_request.cancellation.operation;
    valid.then_some(()).ok_or(ContractError::Invalid)
}

pub(crate) fn response(
    value: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
) -> Result<(), ContractError> {
    let token_lifetime = value
        .token
        .expires_at_epoch_s
        .checked_sub(value.token.issued_at_epoch_s);
    let outer_lifetime = value
        .expires_at_epoch_s
        .checked_sub(value.issued_at_epoch_s);
    let valid = value.schema
        == crate::ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_CLEANUP_COMPLETE_SCHEMA
        && digest(&value.cleanup_complete_id)
        && digest(&value.cleanup_complete_request_sha256)
        && digest(&value.cleanup_id)
        && digest(&value.cancellation_id)
        && digest(&value.acknowledge_command_digest_sha256)
        && digest(&value.acknowledge_result_digest_sha256)
        && reference(&value.source_device_ref)
        && value.cleanup_delivery_completed_revision > 0
        && value.cleanup_complete_config_generation > 0
        && operation_valid(&value.operation)
        && value.operation.state == ManagementOperationState::Cancelled
        && value.snapshot_revision >= value.cleanup_delivery_completed_revision
        && value.config_generation == value.cleanup_complete_config_generation
        && value.token.issued_at_epoch_s <= value.issued_at_epoch_s
        && token_lifetime.is_some_and(|item| (1..=120).contains(&item))
        && outer_lifetime.is_some_and(|item| (1..=30).contains(&item))
        && id(&value.issuer, 256)
        && id(&value.audience, 256)
        && id(&value.key_id, 128)
        && lower_hex(&value.signature, 64)
        && token(value)
        && crate::endpoint_revocation_execution_cancellation_cleanup_complete_id(value)
            .is_ok_and(|item| item == value.cleanup_complete_id);
    valid.then_some(()).ok_or(ContractError::Invalid)
}

fn token(value: &EndpointRevocationExecutionCancellationCleanupCompleteV1) -> bool {
    value.token.schema == SIGNED_EVIDENCE_SCHEMA
        && value.token.role == VerificationRole::RevocationCancellationCleanupComplete
        && value.token.proof_id == value.cleanup_complete_id
        && value.token.binding_sha256 == value.cleanup_complete_request_sha256
        && id(&value.token.key_id, 128)
        && lower_hex(&value.token.signature, 64)
}
