use crate::{
    EndpointPreparedLookupPhaseV1 as P, EndpointPreparedLookupRequestV1,
    EndpointPreparedLookupResponseV1, ManagementIntentV2 as I, ManagementOperationKind as K,
    ManagementOperationScopeV2 as Scope, ManagementOperationState as S, RequiredActorRole as R,
};

pub(crate) fn identity_matches(
    request: &EndpointPreparedLookupRequestV1,
    value: &EndpointPreparedLookupResponseV1,
) -> bool {
    let Ok(identity) = crate::identity_evidence_from_exchange(&request.identity_exchange) else {
        return false;
    };
    let assertion = &identity.assertion;
    value.prepared.pairwise_subject == assertion.pairwise_subject
        && intent_service(&value.prepared.intent) == assertion.service_id
}

pub(crate) fn operation_matches(value: &EndpointPreparedLookupResponseV1) -> bool {
    operation_prepared(&value.operation, &value.prepared)
}

pub(crate) fn operation_prepared(
    operation: &crate::ManagementOperationV2,
    prepared: &crate::EndpointPreparedOperationV2,
) -> bool {
    operation.source_device_ref == prepared.source_device_ref
        && operation.intent_digest_sha256 == prepared.origin_command_digest_sha256
        && operation.created_at_epoch_s >= prepared.issued_at_epoch_s
        && operation.expires_at_epoch_s == prepared.expires_at_epoch_s
        && match (&prepared.intent, &operation.kind, &operation.scope) {
            (
                I::DeviceTransfer {
                    target_device_ref,
                    credential_refs,
                    ..
                },
                K::DeviceTransfer,
                Scope::DeviceTransfer {
                    target_device_ref: target,
                    credential_refs: credentials,
                    ..
                },
            ) => target == target_device_ref && credentials == credential_refs,
            (
                I::DeviceRevocation {
                    target_device_ref,
                    expected_device_revocation_epoch,
                    ..
                },
                K::DeviceRevocation,
                Scope::DeviceRevocation {
                    target_device_ref: target,
                    expected_device_revocation_epoch: epoch,
                    revokes_session_refs,
                    ..
                },
            ) => {
                target == target_device_ref
                    && epoch == expected_device_revocation_epoch
                    && prepared
                        .revocation
                        .as_ref()
                        .and_then(|v| v.expected_revoked_session_count)
                        == Some(revokes_session_refs.len() as u64)
            }
            (
                I::SessionRevocation {
                    target_session_ref,
                    expected_session_revocation_epoch,
                    ..
                },
                K::SessionRevocation,
                Scope::SessionRevocation {
                    target_session_ref: target,
                    expected_session_revocation_epoch: epoch,
                    device_ref,
                },
            ) => {
                target == target_session_ref
                    && epoch == expected_session_revocation_epoch
                    && prepared
                        .revocation
                        .as_ref()
                        .is_some_and(|v| v.target_device_ref == *device_ref)
            }
            _ => false,
        }
}

pub(crate) fn phase(
    request: &EndpointPreparedLookupRequestV1,
    value: &EndpointPreparedLookupResponseV1,
) -> bool {
    let Ok(identity) = crate::identity_evidence_from_exchange(&request.identity_exchange) else {
        return false;
    };
    let actor = &identity.assertion.device_id;
    match request.phase {
        P::Target => {
            value.operation.state == S::AwaitingTarget
                && value.operation.actor.role == R::TargetDevice
                && value.operation.actor.required_actor_device_ref.as_deref() == Some(actor)
                && transfer_target(&value.prepared).is_some_and(|target| target == actor)
        }
        P::Approval => crate::endpoint_prepared_lookup_policy::approval(value, actor),
        P::Cancel => {
            matches!(
                value.operation.state,
                S::AwaitingSourceUv
                    | S::AwaitingTarget
                    | S::AwaitingTargetUv
                    | S::AwaitingIndependentApproval
                    | S::AwaitingApprovalUv
                    | S::AwaitingRevocationFinal
            ) && actor == &value.prepared.source_device_ref
                && (value.operation.state != S::AwaitingRevocationFinal
                    || identity.assertion.session_ref == value.prepared.source_session_ref)
        }
        P::Reconcile => {
            value.operation.state == S::Unknown
                && crate::endpoint_actor_binding::reconcile(identity, &value.prepared).is_ok()
                && value.operation.actor.role == R::ReconcileOnly
        }
    }
}

fn intent_service(value: &I) -> &str {
    match value {
        I::DeviceTransfer { service_id, .. }
        | I::DeviceRevocation { service_id, .. }
        | I::SessionRevocation { service_id, .. } => service_id,
    }
}

fn transfer_target(value: &crate::EndpointPreparedOperationV2) -> Option<&str> {
    match &value.intent {
        I::DeviceTransfer {
            target_device_ref, ..
        } => Some(target_device_ref),
        _ => None,
    }
}
