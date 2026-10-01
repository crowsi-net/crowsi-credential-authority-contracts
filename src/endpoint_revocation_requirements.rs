use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementIntentV2, RevocationRequirementsV2,
};

pub(crate) fn validate(
    value: &EndpointPreparedOperationV2,
) -> Result<&RevocationRequirementsV2, ContractError> {
    let requirements = value.revocation.as_ref().ok_or(ContractError::Invalid)?;
    let shape = match &value.intent {
        ManagementIntentV2::DeviceTransfer { .. } => false,
        ManagementIntentV2::DeviceRevocation {
            target_device_ref, ..
        } => {
            requirements.target_device_ref == *target_device_ref
                && requirements.expected_revoked_session_count.is_some()
        }
        ManagementIntentV2::SessionRevocation { .. } => {
            requirements.expected_revoked_session_count.is_none()
        }
    };
    let approval = requirements.target_device_ref != value.source_device_ref;
    let authority = requirements.required_approval_authority_ref.is_some() == approval;
    if shape
        && authority
        && bounded(&requirements.target_device_ref)
        && bounded(&requirements.finalization_authority_id)
        && requirements
            .required_approval_authority_ref
            .as_ref()
            .is_none_or(|value| bounded(value))
    {
        Ok(requirements)
    } else {
        Err(ContractError::Invalid)
    }
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}
