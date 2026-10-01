use ihat_identity_assertion_contracts::{
    AuthorityCommand, SIGNED_EVIDENCE_SCHEMA, VerificationRole, command_digest,
};

use crate::{
    ContractError, EndpointManagementEvidenceV2, EndpointRevocationExecutionCancelRequestV1,
    EndpointRevocationExecutionCancellationV1, ManagementCommandV2, ManagementOperationState,
    management_operation_validation::{digest, id, lower_hex, operation_valid, reference},
};

pub(crate) fn request(
    value: &EndpointRevocationExecutionCancelRequestV1,
) -> Result<(), ContractError> {
    crate::endpoint_envelope_validation::validate(&value.cancel_envelope)?;
    crate::endpoint_envelope_validation::validate_prepared_shape(&value.prepared)?;
    let ManagementCommandV2::Cancel {
        operation_id,
        expected_state_revision: expected,
    } = &value.cancel_envelope.browser_request.command
    else {
        return Err(ContractError::Invalid);
    };
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange,
        prepared,
    } = &value.cancel_envelope.evidence
    else {
        return Err(ContractError::Invalid);
    };
    let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
    let valid = value.schema == crate::ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA
        && id(&value.request_id, 128)
        && digest(&value.operation_id)
        && digest(&value.pre_final_acceptance_request_sha256)
        && operation_id == &value.operation_id
        && expected.checked_add(1) == Some(value.expected_cancelled_state_revision)
        && value.expected_cancelled_state_revision > 0
        && prepared == &value.prepared
        && value.operation_id == value.prepared.operation_id
        && identity.assertion.device_id == value.prepared.source_device_ref
        && identity.assertion.session_ref == value.prepared.source_session_ref;
    if !valid {
        return Err(ContractError::Invalid);
    }
    crate::endpoint_identity_context::identity_pair(identity)?;
    crate::endpoint_identity_context::operation(identity, &value.prepared)?;
    crate::endpoint_revocation_begin::validate(&value.prepared, &value.begin_exchange, None)?;
    Ok(())
}

pub(crate) fn cancellation(
    value: &EndpointRevocationExecutionCancellationV1,
) -> Result<(), ContractError> {
    let token_lifetime = value
        .token
        .expires_at_epoch_s
        .checked_sub(value.token.issued_at_epoch_s);
    let outer_lifetime = value
        .expires_at_epoch_s
        .checked_sub(value.issued_at_epoch_s);
    let valid = value.schema == crate::ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_SCHEMA
        && digest(&value.cancellation_id)
        && stable(value)
        && operation_valid(&value.operation)
        && value.operation.state == ManagementOperationState::Cancelled
        && value.operation.state_revision == value.cancelled_state_revision
        && value.snapshot_revision > 0
        && value.execution_reservation_id.is_none()
        && value.cancellation_config_generation > 0
        && value.cancellation_accepted_revision > 0
        && value.snapshot_revision >= value.cancellation_accepted_revision
        && value.config_generation == value.cancellation_config_generation
        && value.token.issued_at_epoch_s <= value.issued_at_epoch_s
        && token_lifetime.is_some_and(|item| (1..=120).contains(&item))
        && outer_lifetime.is_some_and(|item| (1..=30).contains(&item))
        && token(value)
        && cancel_command(value)
        && crate::endpoint_revocation_execution_cancellation_id(value)
            .is_ok_and(|item| item == value.cancellation_id);
    valid.then_some(()).ok_or(ContractError::Invalid)
}

fn stable(value: &EndpointRevocationExecutionCancellationV1) -> bool {
    [
        &value.cancellation_request_sha256,
        &value.cancel_envelope_digest_sha256,
        &value.pre_final_acceptance_request_sha256,
        &value.prepared_operation_digest_sha256,
        &value.target_digest_sha256,
        &value.begin_exchange_digest_sha256,
        &value.begin_command_digest_sha256,
    ]
    .into_iter()
    .all(|item| digest(item))
        && reference(&value.opaque_owner_ref)
        && id(&value.service_id, 128)
        && reference(&value.pairwise_subject)
        && reference(&value.source_device_ref)
        && reference(&value.source_session_ref)
        && digest(&value.finalize_command_id)
        && id(&value.issuer, 256)
        && id(&value.audience, 256)
        && id(&value.key_id, 128)
        && lower_hex(&value.signature, 64)
}

include!("endpoint_revocation_execution_cancel_validation_support.rs");
