use crowsi_credential_authority_contracts::*;

use crate::{
    endpoint_actor_support::transfer_prepared,
    endpoint_revocation_values::{actor, identity_exchange},
};

const NOW: u64 = 110;

pub(crate) fn target_request() -> EndpointPreparedLookupRequestV1 {
    let identity = actor("device-b", 'b');
    EndpointPreparedLookupRequestV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA.into(),
        request_id: "lookup-request-a".into(),
        operation_id: transfer_prepared().operation_id,
        expected_state_revision: 2,
        phase: EndpointPreparedLookupPhaseV1::Target,
        identity_exchange: identity_exchange(&identity),
    }
}

pub(crate) fn response(
    request: &EndpointPreparedLookupRequestV1,
) -> EndpointPreparedLookupResponseV1 {
    let prepared = transfer_prepared();
    let identity = &identity_evidence_from_exchange(&request.identity_exchange)
        .expect("identity exchange")
        .assertion;
    EndpointPreparedLookupResponseV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_digest_sha256: endpoint_prepared_lookup_request_digest(request).expect("digest"),
        actor_device_ref: identity.device_id.clone(),
        actor_session_ref: identity.session_ref.clone(),
        subject_revocation_epoch: identity.revocation_epochs.subject,
        service_revocation_epoch: identity.revocation_epochs.service,
        device_revocation_epoch: identity.revocation_epochs.device,
        session_revocation_epoch: identity.revocation_epochs.session,
        operation: operation(&request.operation_id),
        prepared,
        revocation_begin_exchange: None,
        pre_final_acceptance_request_sha256: None,
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 20,
        key_id: "lookup-key".into(),
        signature: String::new(),
    }
}

fn operation(id: &str) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: id.into(),
        kind: ManagementOperationKind::DeviceTransfer,
        intent_digest_sha256: "aa".repeat(32),
        state: ManagementOperationState::AwaitingTarget,
        state_revision: 2,
        created_at_epoch_s: NOW - 5,
        expires_at_epoch_s: 400,
        source_device_ref: "device-a".into(),
        scope: ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_source_device_revocation_epoch: 1,
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::TargetDevice,
            required_actor_device_ref: Some("device-b".into()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: vec!["device-a".into()],
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: None,
    }
}
