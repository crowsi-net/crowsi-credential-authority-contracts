use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    endpoint_revocation_exchanges::begin,
    endpoint_revocation_support::prepared,
    endpoint_revocation_values::{actor, fresh, identity_exchange},
};

pub(crate) fn request() -> EndpointPreparedLookupRequestV1 {
    let operation_id = prepared("device-b").operation_id;
    EndpointPreparedLookupRequestV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA.into(),
        request_id: "approval-lookup".into(),
        operation_id,
        expected_state_revision: 3,
        phase: EndpointPreparedLookupPhaseV1::Approval,
        identity_exchange: identity_exchange(&actor("device-c", 'c')),
    }
}

pub(crate) fn response(
    request: &EndpointPreparedLookupRequestV1,
) -> EndpointPreparedLookupResponseV1 {
    let prepared = prepared("device-b");
    let source = actor("device-a", 'a');
    let source_fresh = fresh(&source, &prepared, "source-uv", "credential-a");
    let revocation_begin_exchange =
        matches!(request.phase, EndpointPreparedLookupPhaseV1::Approval)
            .then(|| begin(&prepared, &source_fresh, true));
    let assertion = &identity_evidence_from_exchange(&request.identity_exchange)
        .expect("identity exchange")
        .assertion;
    EndpointPreparedLookupResponseV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_digest_sha256: endpoint_prepared_lookup_request_digest(request).expect("digest"),
        actor_device_ref: assertion.device_id.clone(),
        actor_session_ref: assertion.session_ref.clone(),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        operation: operation(&prepared),
        prepared,
        revocation_begin_exchange,
        pre_final_acceptance_request_sha256: None,
        issued_at_epoch_s: 109,
        expires_at_epoch_s: 130,
        key_id: "lookup-key".into(),
        signature: String::new(),
    }
}

fn operation(prepared: &EndpointPreparedOperationV2) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceRevocation,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingIndependentApproval,
        state_revision: 3,
        created_at_epoch_s: 105,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: "device-a".into(),
        scope: ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref: "device-b".into(),
            expected_device_revocation_epoch: 1,
            revokes_session_refs: vec!["session-b-1".into(), "session-b-2".into()],
            rotates_credential_refs: vec![],
            preserves_device_refs: vec!["device-a".into()],
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::IndependentApproval,
            required_actor_device_ref: None,
            required_approval_authority_ref: Some("recovery-authority-c".into()),
            excluded_actor_device_refs: vec!["device-a".into(), "device-b".into()],
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: None,
    }
}

pub(crate) fn sign(value: &mut EndpointPreparedLookupResponseV1, key: &SigningKey) {
    value.signature = hex::encode(
        key.sign(&canonical_endpoint_prepared_lookup_response(value).expect("canonical"))
            .to_bytes(),
    );
}

pub(crate) fn verify(
    value: &EndpointPreparedLookupResponseV1,
    request: &EndpointPreparedLookupRequestV1,
    key: &SigningKey,
) -> Result<(), ContractError> {
    verify_endpoint_prepared_lookup_response_at(
        value,
        request,
        "lookup-key",
        &hex::encode(key.verifying_key().to_bytes()),
        110,
    )
}
