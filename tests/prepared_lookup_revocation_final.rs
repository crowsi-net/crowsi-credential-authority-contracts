use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    endpoint_revocation_support::prepared,
    endpoint_revocation_values::{actor, identity_exchange},
};

#[test]
fn awaiting_final_cancel_requires_the_exact_source_session() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let mut request = request('a');
    let mut response = response(&request);
    sign(&mut response, &key);
    verify(&response, &request, &key).expect("same source session can cancel");

    request.identity_exchange = identity_exchange(&actor("device-a", 'z'));
    response.request_digest_sha256 =
        endpoint_prepared_lookup_request_digest(&request).expect("digest");
    let identity = identity_evidence_from_exchange(&request.identity_exchange).expect("identity");
    response.actor_session_ref = identity.assertion.session_ref.clone();
    sign(&mut response, &key);
    assert_eq!(
        verify(&response, &request, &key),
        Err(ContractError::Invalid)
    );
}

#[test]
fn awaiting_final_cancel_requires_the_signed_pre_final_acceptance_digest() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let request = request('a');
    let mut valid = response(&request);
    sign(&mut valid, &key);
    verify(&valid, &request, &key).expect("central acceptance claim");

    for digest in [None, Some("55".repeat(31)), Some("GG".repeat(32))] {
        let mut changed = valid.clone();
        changed.pre_final_acceptance_request_sha256 = digest;
        sign(&mut changed, &key);
        assert_eq!(
            verify(&changed, &request, &key),
            Err(ContractError::Invalid)
        );
    }
    let mut missing = serde_json::to_value(&valid).expect("json");
    missing
        .as_object_mut()
        .expect("object")
        .remove("pre_final_acceptance_request_sha256");
    assert_eq!(
        decode_endpoint_prepared_lookup_response_strict(
            &serde_json::to_vec(&missing).expect("wire")
        ),
        Err(ContractError::Invalid)
    );
}

fn request(session: char) -> EndpointPreparedLookupRequestV1 {
    EndpointPreparedLookupRequestV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA.into(),
        request_id: "cancel-awaiting-final".into(),
        operation_id: prepared("device-a").operation_id,
        expected_state_revision: 2,
        phase: EndpointPreparedLookupPhaseV1::Cancel,
        identity_exchange: identity_exchange(&actor("device-a", session)),
    }
}

fn response(request: &EndpointPreparedLookupRequestV1) -> EndpointPreparedLookupResponseV1 {
    let prepared = prepared("device-a");
    let assertion = &identity_evidence_from_exchange(&request.identity_exchange)
        .expect("identity")
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
        operation: ManagementOperationV2 {
            operation_id: prepared.operation_id.clone(),
            kind: ManagementOperationKind::DeviceRevocation,
            intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
            state: ManagementOperationState::AwaitingRevocationFinal,
            state_revision: 2,
            created_at_epoch_s: 105,
            expires_at_epoch_s: prepared.expires_at_epoch_s,
            source_device_ref: "device-a".into(),
            scope: ManagementOperationScopeV2::DeviceRevocation {
                target_device_ref: "device-a".into(),
                expected_device_revocation_epoch: 1,
                revokes_session_refs: vec!["session-a".into(), "session-b".into()],
                rotates_credential_refs: Vec::new(),
                preserves_device_refs: Vec::new(),
            },
            actor: ActorRequirementV2 {
                role: RequiredActorRole::ReconcileOnly,
                required_actor_device_ref: None,
                required_approval_authority_ref: None,
                excluded_actor_device_refs: Vec::new(),
            },
            webauthn_options: None,
            reason: None,
            reconcile_digest: Some("44".repeat(32)),
        },
        prepared,
        revocation_begin_exchange: None,
        pre_final_acceptance_request_sha256: Some("55".repeat(32)),
        issued_at_epoch_s: 109,
        expires_at_epoch_s: 130,
        key_id: "lookup-key".into(),
        signature: String::new(),
    }
}

fn sign(value: &mut EndpointPreparedLookupResponseV1, key: &SigningKey) {
    value.signature = hex::encode(
        key.sign(&canonical_endpoint_prepared_lookup_response(value).expect("canonical"))
            .to_bytes(),
    );
}

fn verify(
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
