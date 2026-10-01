use ihat_identity_assertion_contracts::{
    IdentityEvidenceMetadata, current_status_matches_assertion,
};

use crate::{ContractError, EndpointPreparedOperationV2};

pub(crate) fn creation_source(
    identity: &IdentityEvidenceMetadata,
    value: &EndpointPreparedOperationV2,
) -> Result<(), ContractError> {
    identity_pair(identity)?;
    operation(identity, value)?;
    (value.source_identity_nonce == identity.assertion.nonce
        && value.source_device_ref == identity.assertion.device_id
        && value.source_session_ref == identity.assertion.session_ref)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

pub(crate) fn current_source(
    identity: &IdentityEvidenceMetadata,
    value: &EndpointPreparedOperationV2,
) -> Result<(), ContractError> {
    identity_pair(identity)?;
    operation(identity, value)?;
    (value.source_device_ref == identity.assertion.device_id)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

pub(crate) fn selected_source(
    identity: &IdentityEvidenceMetadata,
    value: &EndpointPreparedOperationV2,
) -> Result<(), ContractError> {
    identity_pair(identity)?;
    operation(identity, value)?;
    (value.source_device_ref == identity.assertion.device_id
        && value.source_session_ref == identity.assertion.session_ref)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

pub(crate) fn operation(
    identity: &IdentityEvidenceMetadata,
    value: &EndpointPreparedOperationV2,
) -> Result<(), ContractError> {
    let service = match &value.intent {
        crate::ManagementIntentV2::DeviceTransfer { service_id, .. }
        | crate::ManagementIntentV2::DeviceRevocation { service_id, .. }
        | crate::ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    };
    (value.pairwise_subject == identity.assertion.pairwise_subject
        && *service == identity.assertion.service_id)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

pub(crate) fn identity_pair(value: &IdentityEvidenceMetadata) -> Result<(), ContractError> {
    current_status_matches_assertion(&value.current_status, &value.assertion)
        .then_some(())
        .ok_or(ContractError::Invalid)
}
