use ihat_identity_assertion_contracts::{
    IdentityEvidenceMetadata, current_status_matches_assertion,
};

use crate::{ContractError, EndpointPreparedOperationV2, ManagementCommandV2, ManagementIntentV2};

pub(crate) fn options(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    command: &ManagementCommandV2,
) -> Result<(), ContractError> {
    let actor = &identity.assertion.device_id;
    let exact = match (command, &prepared.intent) {
        (
            ManagementCommandV2::TargetOptions { .. },
            ManagementIntentV2::DeviceTransfer {
                target_device_ref, ..
            },
        ) => actor == target_device_ref && actor != &prepared.source_device_ref,
        (ManagementCommandV2::ApprovalOptions { .. }, intent)
            if !matches!(intent, ManagementIntentV2::DeviceTransfer { .. }) =>
        {
            crate::endpoint_revocation_binding::requirements(prepared).is_ok_and(|requirements| {
                requirements.required_approval_authority_ref.is_some()
                    && actor != &prepared.source_device_ref
                    && actor != &requirements.target_device_ref
            })
        }
        _ => false,
    };
    exact.then_some(()).ok_or(ContractError::Invalid)
}

pub(crate) fn reconcile(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
) -> Result<(), ContractError> {
    if !current_status_matches_assertion(&identity.current_status, &identity.assertion) {
        return Err(ContractError::Invalid);
    }
    let service = match &prepared.intent {
        ManagementIntentV2::DeviceTransfer { service_id, .. }
        | ManagementIntentV2::DeviceRevocation { service_id, .. }
        | ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    };
    let identity_matches = identity.assertion.service_id == *service
        && identity.assertion.pairwise_subject == prepared.pairwise_subject;
    let actor_allowed = if matches!(prepared.intent, ManagementIntentV2::DeviceTransfer { .. }) {
        true
    } else {
        crate::endpoint_revocation_binding::requirements(prepared).is_ok_and(|requirements| {
            identity.assertion.device_id != prepared.source_device_ref
                && identity.assertion.device_id != requirements.target_device_ref
        })
    };
    (identity_matches && actor_allowed)
        .then_some(())
        .ok_or(ContractError::Invalid)
}
