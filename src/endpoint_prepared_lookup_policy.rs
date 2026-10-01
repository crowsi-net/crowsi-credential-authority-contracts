use crate::{
    EndpointPreparedLookupResponseV1, ManagementIntentV2 as I, ManagementOperationState as S,
    RequiredActorRole as R,
};

pub(crate) fn approval(value: &EndpointPreparedLookupResponseV1, actor: &str) -> bool {
    let Some(requirements) = value.prepared.revocation.as_ref() else {
        return false;
    };
    let role = &value.operation.actor;
    value.operation.state == S::AwaitingIndependentApproval
        && !matches!(value.prepared.intent, I::DeviceTransfer { .. })
        && role.role == R::IndependentApproval
        && actor != value.prepared.source_device_ref
        && actor != requirements.target_device_ref
        && role
            .excluded_actor_device_refs
            .contains(&value.prepared.source_device_ref)
        && role
            .excluded_actor_device_refs
            .contains(&requirements.target_device_ref)
        && role.required_actor_device_ref.as_deref().map_or_else(
            || role.required_approval_authority_ref == requirements.required_approval_authority_ref,
            |required| required == actor,
        )
}
