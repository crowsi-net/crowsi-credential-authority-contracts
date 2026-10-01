use ihat_identity_assertion_contracts::{AuthorityEvidence, VerificationRole, command_digest};

use crate::{
    ContractError, EndpointIndependentRevocationFinalizeRequestV1, ManagementCommandV2,
    RevocationIndependentPreFinalCeremonyV1,
    management_operation_validation::{digest, id},
};

pub(crate) fn validate(
    value: &EndpointIndependentRevocationFinalizeRequestV1,
) -> Result<(), ContractError> {
    let command = &value.approve_revocation_request.command;
    let exact_command = matches!(command, ManagementCommandV2::ApproveRevocation {
        operation_id,
        expected_state_revision,
        ..
    } if operation_id == &value.operation_id
        && expected_state_revision.checked_add(1) == Some(value.pre_final_state_revision)
        && value.pre_final_state_revision.checked_add(1) == Some(value.expected_state_revision));
    if value.schema != crate::ENDPOINT_INDEPENDENT_REVOCATION_FINALIZE_REQUEST_SCHEMA
        || !id(&value.request_id, 128)
        || !digest(&value.operation_id)
        || !digest(&value.reconcile_digest)
        || !digest(&value.pre_final_request_sha256)
        || !digest(&value.execution_reservation_id)
        || value.operation_id != value.prepared.operation_id
        || !exact_command
        || crate::management_request_validation::request(&value.approve_revocation_request).is_err()
        || crate::endpoint_envelope_validation::validate_prepared_shape(&value.prepared).is_err()
    {
        return Err(ContractError::Invalid);
    }
    ceremony(value)?;
    final_exchange(value)
}

fn ceremony(value: &EndpointIndependentRevocationFinalizeRequestV1) -> Result<(), ContractError> {
    let identity = crate::identity_evidence_from_exchange(&value.accepted_identity_exchange)?;
    crate::endpoint_identity_context::identity_pair(identity)?;
    crate::endpoint_identity_context::operation(identity, &value.prepared)?;
    crate::endpoint_revocation_binding::independent_pre_final(
        identity,
        &value.prepared,
        &RevocationIndependentPreFinalCeremonyV1 {
            begin: value.begin_exchange.clone(),
            approval: value.approval_exchange.clone(),
        },
    )?;
    Ok(())
}

fn final_exchange(
    value: &EndpointIndependentRevocationFinalizeRequestV1,
) -> Result<(), ContractError> {
    let [AuthorityEvidence::Signed(token)] =
        value.final_revoke_exchange.request.evidence.as_slice()
    else {
        return Err(ContractError::Invalid);
    };
    let exact = token == &value.execution_reservation_token
        && token.role == VerificationRole::RevocationExecutionReservation
        && token.proof_id == value.execution_reservation_id
        && token.binding_sha256
            == command_digest(&value.final_revoke_exchange.request)
                .map_err(|_| ContractError::Invalid)?
        && value.final_revoke_exchange.response.key_id == value.begin_exchange.response.key_id
        && value.final_revoke_exchange.response.config_generation
            >= value.approval_exchange.response.config_generation
        && value.final_revoke_exchange.response.issued_at_epoch_s >= token.issued_at_epoch_s;
    if !exact {
        return Err(ContractError::Invalid);
    }
    let target =
        crate::endpoint_revocation_final::shape(&value.prepared, &value.final_revoke_exchange)?;
    let begun =
        crate::endpoint_revocation_begin::validate(&value.prepared, &value.begin_exchange, None)?;
    (target == begun.target_digest)
        .then_some(())
        .ok_or(ContractError::Invalid)
}
