use crate::management_operation_validation::{digest, id, reference};
use crate::{
    ContractError, ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, EndpointPreparedOperationV2, ManagementCommandV2,
    management_command_digest,
};

pub(crate) fn validate(value: &EndpointManagementEnvelopeV2) -> Result<(), ContractError> {
    crate::management_request_validation::request(&value.browser_request)?;
    let matches = matches!(
        (&value.browser_request.command, &value.evidence),
        (
            ManagementCommandV2::Snapshot { .. } | ManagementCommandV2::PendingList { .. },
            EndpointManagementEvidenceV2::Passive { .. }
        ) | (
            ManagementCommandV2::SourceOptions { .. },
            EndpointManagementEvidenceV2::SourceOptions { .. }
        ) | (
            ManagementCommandV2::SourceApprove { .. },
            EndpointManagementEvidenceV2::SourceApprove { .. }
        ) | (
            ManagementCommandV2::TargetOptions { .. } | ManagementCommandV2::ApprovalOptions { .. },
            EndpointManagementEvidenceV2::ActorOptions { .. }
        ) | (
            ManagementCommandV2::TargetApprove { .. },
            EndpointManagementEvidenceV2::TargetApprove { .. }
        ) | (
            ManagementCommandV2::ApproveRevocation { .. },
            EndpointManagementEvidenceV2::IndependentApprove { .. }
        ) | (
            ManagementCommandV2::Cancel { .. },
            EndpointManagementEvidenceV2::Cancel { .. }
        ) | (
            ManagementCommandV2::Reconcile { .. },
            EndpointManagementEvidenceV2::Reconcile { .. }
        )
    );
    if value.schema != ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA || !matches {
        return Err(ContractError::Invalid);
    }
    if let Some(prepared) = prepared(&value.evidence) {
        validate_prepared(value, prepared)?;
    }
    crate::endpoint_identity_binding::validate(value)?;
    crate::management_validation_support::bounded(value)
}

pub(crate) fn validate_prepared_shape(
    value: &EndpointPreparedOperationV2,
) -> Result<(), ContractError> {
    if crate::endpoint_operation_id(value).is_ok_and(|id| id == value.operation_id)
        && digest(&value.origin_command_digest_sha256)
        && reference(&value.source_device_ref)
        && reference(&value.source_session_ref)
        && reference(&value.pairwise_subject)
        && reference(&value.opaque_owner_ref)
        && id(&value.source_identity_nonce, 128)
        && id(&value.nonce, 128)
        && value.issued_at_epoch_s < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 300
        && revocation_shape(value)
    {
        Ok(())
    } else {
        Err(ContractError::Invalid)
    }
}

fn validate_prepared(
    envelope: &EndpointManagementEnvelopeV2,
    value: &EndpointPreparedOperationV2,
) -> Result<(), ContractError> {
    let current_digest = management_command_digest(&envelope.browser_request)?;
    let (operation_matches, origin_matches) = match &envelope.browser_request.command {
        ManagementCommandV2::SourceOptions { intent } => (
            value.intent == *intent,
            value.origin_command_digest_sha256 == current_digest,
        ),
        ManagementCommandV2::SourceApprove { operation_id, .. }
        | ManagementCommandV2::TargetOptions { operation_id, .. }
        | ManagementCommandV2::TargetApprove { operation_id, .. }
        | ManagementCommandV2::ApprovalOptions { operation_id, .. }
        | ManagementCommandV2::ApproveRevocation { operation_id, .. }
        | ManagementCommandV2::Cancel { operation_id, .. }
        | ManagementCommandV2::Reconcile { operation_id, .. } => {
            (operation_id == &value.operation_id, true)
        }
        _ => (false, false),
    };
    validate_prepared_shape(value)?;
    (origin_matches && operation_matches)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

fn revocation_shape(value: &EndpointPreparedOperationV2) -> bool {
    match value.intent {
        crate::ManagementIntentV2::DeviceTransfer { .. } => value.revocation.is_none(),
        crate::ManagementIntentV2::DeviceRevocation { .. }
        | crate::ManagementIntentV2::SessionRevocation { .. } => {
            crate::endpoint_revocation_binding::requirements(value).is_ok()
        }
    }
}

fn prepared(value: &EndpointManagementEvidenceV2) -> Option<&EndpointPreparedOperationV2> {
    match value {
        EndpointManagementEvidenceV2::Passive { .. } => None,
        EndpointManagementEvidenceV2::SourceOptions { prepared, .. }
        | EndpointManagementEvidenceV2::SourceApprove { prepared, .. }
        | EndpointManagementEvidenceV2::ActorOptions { prepared, .. }
        | EndpointManagementEvidenceV2::TargetApprove { prepared, .. }
        | EndpointManagementEvidenceV2::IndependentApprove { prepared, .. }
        | EndpointManagementEvidenceV2::Cancel { prepared, .. }
        | EndpointManagementEvidenceV2::Reconcile { prepared, .. } => Some(prepared),
    }
}
