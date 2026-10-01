use crate::{
    ContractError, EndpointIndependentRevocationPreFinalRequestV1, ManagementCommandV2,
    management_operation_validation::{digest, id},
};

pub(crate) fn validate(
    value: &EndpointIndependentRevocationPreFinalRequestV1,
) -> Result<(), ContractError> {
    let command = &value.approve_revocation_request.command;
    let exact_command = matches!(command, ManagementCommandV2::ApproveRevocation {
        operation_id,
        expected_state_revision,
        ..
    } if operation_id == &value.operation_id
        && *expected_state_revision == value.expected_state_revision);
    if value.schema != crate::ENDPOINT_INDEPENDENT_REVOCATION_PRE_FINAL_REQUEST_SCHEMA
        || !id(&value.request_id, 128)
        || !digest(&value.operation_id)
        || value.expected_state_revision == 0
        || value.operation_id != value.prepared.operation_id
        || !exact_command
        || crate::management_request_validation::request(&value.approve_revocation_request).is_err()
        || crate::endpoint_envelope_validation::validate_prepared_shape(&value.prepared).is_err()
    {
        return Err(ContractError::Invalid);
    }
    approval_chain(value)
}

fn approval_chain(
    value: &EndpointIndependentRevocationPreFinalRequestV1,
) -> Result<(), ContractError> {
    let selected = crate::identity_evidence_from_exchange(&value.selected_identity_exchange)?;
    let accepted = crate::identity_evidence_from_exchange(&value.accepted_identity_exchange)?;
    let command = &value.approve_revocation_request.command;
    let fresh = crate::fresh_uv_from_finish_exchange(&value.finish_uv_exchange, command)?;
    crate::endpoint_identity_context::identity_pair(selected)?;
    crate::endpoint_identity_context::operation(selected, &value.prepared)?;
    crate::endpoint_identity_operation::options(
        selected,
        &value.prepared,
        &value.begin_uv_exchange,
    )?;
    crate::validate_finish_uv_continuity(
        &value.begin_uv_exchange,
        &value.finish_uv_exchange,
        command,
    )?;
    crate::endpoint_identity_context::identity_pair(accepted)?;
    crate::endpoint_identity_context::operation(accepted, &value.prepared)?;
    crate::endpoint_identity_operation::fresh(accepted, &value.prepared, fresh, command)?;
    crate::endpoint_revocation_binding::independent_pre_final(
        accepted,
        &value.prepared,
        &value.revocation_ceremony,
    )?;
    Ok(())
}
