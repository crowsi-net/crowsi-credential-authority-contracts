use crate::management_operation_validation::{base64, digest, id, reference};
use crate::management_validation_support::references_allow_empty;
use crate::{
    ActorRequirementV2, ManagementOperationKind, ManagementOperationScopeV2,
    ManagementOperationState, ManagementOperationV2, ManagementReasonCode, RequiredActorRole,
    WebAuthnOptionsV2,
};

pub(crate) fn actor_valid(value: &ManagementOperationV2) -> bool {
    references_allow_empty(&value.actor.excluded_actor_device_refs, 100)
        && actor_state(value)
        && option_state(value)
        && outcome_state(value)
}
fn actor_state(value: &ManagementOperationV2) -> bool {
    let actor = &value.actor;
    match value.state {
        ManagementOperationState::AwaitingSourceUv => {
            actor.role == RequiredActorRole::SourceDevice
                && actor.required_actor_device_ref.as_deref() == Some(&value.source_device_ref)
                && actor.required_approval_authority_ref.is_none()
        }
        ManagementOperationState::AwaitingTarget | ManagementOperationState::AwaitingTargetUv => {
            value.kind == ManagementOperationKind::DeviceTransfer
                && actor.role == RequiredActorRole::TargetDevice
                && actor.required_actor_device_ref.as_deref() == Some(target_device(&value.scope))
                && actor.required_approval_authority_ref.is_none()
                && actor
                    .excluded_actor_device_refs
                    .contains(&value.source_device_ref)
        }
        ManagementOperationState::AwaitingIndependentApproval
        | ManagementOperationState::AwaitingApprovalUv => {
            value.kind != ManagementOperationKind::DeviceTransfer && independent(value)
        }
        ManagementOperationState::AwaitingRevocationFinal
        | ManagementOperationState::RevocationExecutionReserved => {
            value.kind != ManagementOperationKind::DeviceTransfer
                && actor.role == RequiredActorRole::ReconcileOnly
                && no_actor(actor)
        }
        ManagementOperationState::Executing => {
            actor.role == RequiredActorRole::Authority && no_actor(actor)
        }
        ManagementOperationState::Unknown => {
            actor.role == RequiredActorRole::ReconcileOnly && no_actor(actor)
        }
        ManagementOperationState::Completed
        | ManagementOperationState::Rejected
        | ManagementOperationState::Cancelled
        | ManagementOperationState::Expired => {
            actor.role == RequiredActorRole::NoActor && no_actor(actor)
        }
    }
}
fn independent(value: &ManagementOperationV2) -> bool {
    let actor = &value.actor;
    actor.role == RequiredActorRole::IndependentApproval
        && (actor
            .required_actor_device_ref
            .as_deref()
            .is_some_and(reference)
            ^ actor
                .required_approval_authority_ref
                .as_deref()
                .is_some_and(reference))
        && actor
            .excluded_actor_device_refs
            .contains(&value.source_device_ref)
        && actor
            .excluded_actor_device_refs
            .iter()
            .any(|v| v == target_device(&value.scope))
        && actor
            .required_actor_device_ref
            .as_deref()
            .is_none_or(|required| {
                !actor
                    .excluded_actor_device_refs
                    .iter()
                    .any(|v| v == required)
            })
}
fn no_actor(actor: &ActorRequirementV2) -> bool {
    actor.required_actor_device_ref.is_none()
        && actor.required_approval_authority_ref.is_none()
        && actor.excluded_actor_device_refs.is_empty()
}
fn option_state(value: &ManagementOperationV2) -> bool {
    let expected = matches!(
        value.state,
        ManagementOperationState::AwaitingSourceUv
            | ManagementOperationState::AwaitingTargetUv
            | ManagementOperationState::AwaitingApprovalUv
    );
    value.webauthn_options.is_some() == expected
        && value.webauthn_options.as_ref().is_none_or(options_valid)
}
fn outcome_state(value: &ManagementOperationV2) -> bool {
    match value.state {
        ManagementOperationState::AwaitingRevocationFinal
        | ManagementOperationState::RevocationExecutionReserved => {
            value.reconcile_digest.as_deref().is_some_and(digest) && value.reason.is_none()
        }
        ManagementOperationState::Unknown => {
            value.reconcile_digest.as_deref().is_some_and(digest)
                && value.reason == Some(ManagementReasonCode::ProviderOutcomeUnknown)
        }
        ManagementOperationState::Rejected
        | ManagementOperationState::Cancelled
        | ManagementOperationState::Expired => {
            value.reason.is_some() && value.reconcile_digest.is_none()
        }
        _ => value.reason.is_none() && value.reconcile_digest.is_none(),
    }
}
fn target_device(scope: &ManagementOperationScopeV2) -> &str {
    match scope {
        ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref, ..
        }
        | ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref, ..
        } => target_device_ref,
        ManagementOperationScopeV2::SessionRevocation { device_ref, .. } => device_ref,
    }
}
fn options_valid(value: &WebAuthnOptionsV2) -> bool {
    id(&value.attempt_id, 128)
        && base64(&value.challenge, 4096)
        && id(&value.rp_id, 253)
        && id(&value.origin, 512)
        && id(&value.credential_id, 128)
        && (1..=120_000).contains(&value.timeout_ms)
        && value.expires_at_epoch_s > 0
        && digest(&value.command_binding_sha256)
}
