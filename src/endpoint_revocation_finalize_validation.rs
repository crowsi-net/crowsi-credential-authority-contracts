use ihat_identity_assertion_contracts::{AuthorityEvidence, VerificationRole, command_digest};

use crate::{
    ContractError, ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA,
    EndpointRevocationFinalizeRequestV1,
    management_operation_validation::{digest, id},
};

pub(crate) fn validate(value: &EndpointRevocationFinalizeRequestV1) -> Result<(), ContractError> {
    let identity = crate::identity_evidence_from_exchange(&value.accepted_identity_exchange)?;
    let assertion = &identity.assertion;
    let source_approve = matches!(
        &value.source_approve_request.command,
        crate::ManagementCommandV2::SourceApprove {
            operation_id,
            expected_state_revision,
            ..
        } if operation_id == &value.operation_id
            && expected_state_revision.checked_add(1) == Some(value.pre_final_state_revision)
            && value.pre_final_state_revision.checked_add(1)
                == Some(value.expected_state_revision)
    );
    let valid = value.schema == ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA
        && id(&value.request_id, 128)
        && digest(&value.operation_id)
        && value.operation_id == value.prepared.operation_id
        && digest(&value.reconcile_digest)
        && digest(&value.pre_final_request_sha256)
        && digest(&value.execution_reservation_id)
        && crate::management_request_validation::request(&value.source_approve_request).is_ok()
        && source_approve
        && crate::endpoint_envelope_validation::validate_prepared_shape(&value.prepared).is_ok()
        && assertion.device_id == value.prepared.source_device_ref
        && assertion.session_ref == value.prepared.source_session_ref
        && assertion.pairwise_subject == value.prepared.pairwise_subject
        && assertion.service_id == intent_service(&value.prepared.intent)
        && final_exact(value).is_ok();
    valid.then_some(()).ok_or(ContractError::Invalid)
}

fn final_exact(value: &EndpointRevocationFinalizeRequestV1) -> Result<(), ContractError> {
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
        && value.final_revoke_exchange.response.issued_at_epoch_s >= token.issued_at_epoch_s;
    if !exact {
        return Err(ContractError::Invalid);
    }
    crate::endpoint_revocation_final::shape(&value.prepared, &value.final_revoke_exchange)?;
    Ok(())
}

fn intent_service(value: &crate::ManagementIntentV2) -> &str {
    match value {
        crate::ManagementIntentV2::DeviceTransfer { service_id, .. }
        | crate::ManagementIntentV2::DeviceRevocation { service_id, .. }
        | crate::ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    }
}
