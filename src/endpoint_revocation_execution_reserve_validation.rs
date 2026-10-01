use ihat_identity_assertion_contracts::{SIGNED_EVIDENCE_SCHEMA, VerificationRole};

use crate::{
    ContractError, EndpointRevocationExecutionReservationV1,
    EndpointRevocationExecutionReserveRequestV1, ManagementCommandV2, ManagementOperationState,
    management_operation_validation::{digest, id, lower_hex, operation_valid, reference},
};

pub(crate) fn request(
    value: &EndpointRevocationExecutionReserveRequestV1,
) -> Result<(), ContractError> {
    if value.schema != crate::ENDPOINT_REVOCATION_EXECUTION_RESERVE_REQUEST_SCHEMA
        || !id(&value.request_id, 128)
        || !digest(&value.operation_id)
        || value.expected_state_revision == 0
        || !digest(&value.reconcile_digest)
        || !digest(&value.pre_final_acceptance_request_sha256)
        || value.operation_id != value.prepared.operation_id
        || crate::management_request_validation::request(&value.original_request).is_err()
        || crate::endpoint_envelope_validation::validate_prepared_shape(&value.prepared).is_err()
        || !original(value)
    {
        return Err(ContractError::Invalid);
    }
    identities(value)?;
    ceremony(value)?;
    crate::endpoint_revocation_final::request(&value.prepared, &value.final_revoke_request)
}

fn original(value: &EndpointRevocationExecutionReserveRequestV1) -> bool {
    matches!(
        &value.original_request.command,
        ManagementCommandV2::SourceApprove {
            operation_id,
            expected_state_revision,
            ..
        } | ManagementCommandV2::ApproveRevocation {
            operation_id,
            expected_state_revision,
            ..
        } if operation_id == &value.operation_id
            && expected_state_revision.checked_add(1) == Some(value.expected_state_revision)
    )
}

fn identities(value: &EndpointRevocationExecutionReserveRequestV1) -> Result<(), ContractError> {
    let accepted = crate::identity_evidence_from_exchange(&value.accepted_identity_exchange)?;
    let current = crate::identity_evidence_from_exchange(&value.reservation_identity_exchange)?;
    crate::endpoint_identity_context::identity_pair(accepted)?;
    crate::endpoint_identity_context::identity_pair(current)?;
    crate::endpoint_identity_context::operation(accepted, &value.prepared)?;
    crate::endpoint_identity_context::operation(current, &value.prepared)?;
    let old = &accepted.assertion;
    let new = &current.assertion;
    (old.device_id == new.device_id
        && old.service_id == new.service_id
        && old.pairwise_subject == new.pairwise_subject)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

fn ceremony(value: &EndpointRevocationExecutionReserveRequestV1) -> Result<(), ContractError> {
    let identity = crate::identity_evidence_from_exchange(&value.accepted_identity_exchange)?;
    match (&value.original_request.command, &value.approval_exchange) {
        (ManagementCommandV2::SourceApprove { .. }, None) => {
            crate::endpoint_revocation_begin::validate(
                &value.prepared,
                &value.begin_exchange,
                None,
            )?;
            (identity.assertion.device_id == value.prepared.source_device_ref
                && value
                    .prepared
                    .revocation
                    .as_ref()
                    .is_some_and(|item| item.target_device_ref == value.prepared.source_device_ref))
            .then_some(())
            .ok_or(ContractError::Invalid)
        }
        (ManagementCommandV2::ApproveRevocation { .. }, Some(approval)) => {
            crate::endpoint_revocation_binding::independent_pre_final(
                identity,
                &value.prepared,
                &crate::RevocationIndependentPreFinalCeremonyV1 {
                    begin: value.begin_exchange.clone(),
                    approval: approval.clone(),
                },
            )?;
            Ok(())
        }
        _ => Err(ContractError::Invalid),
    }
}

pub(crate) fn reservation(
    value: &EndpointRevocationExecutionReservationV1,
) -> Result<(), ContractError> {
    let token_lifetime = value
        .token
        .expires_at_epoch_s
        .checked_sub(value.token.issued_at_epoch_s);
    let outer_lifetime = value
        .expires_at_epoch_s
        .checked_sub(value.issued_at_epoch_s);
    let exact = value.schema == crate::ENDPOINT_REVOCATION_EXECUTION_RESERVATION_SCHEMA
        && digest(&value.reservation_id)
        && digests(value)
        && references(value)
        && revisions(value)
        && operation_valid(&value.operation)
        && token_lifetime.is_some_and(|item| (1..=120).contains(&item))
        && outer_lifetime.is_some_and(|item| (1..=30).contains(&item))
        && token(value);
    exact.then_some(()).ok_or(ContractError::Invalid)
}

include!("endpoint_revocation_execution_reserve_validation_support.rs");
