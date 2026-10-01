use crowsi_credential_authority_contracts::*;
use ed25519_dalek::SigningKey;

use crate::{
    endpoint_revocation_support::prepared,
    endpoint_revocation_values::{actor, identity_exchange},
    prepared_lookup_revocation_support::{request, response, sign, verify},
};

#[test]
fn approval_lookup_binds_resolved_target_authority_and_child_session_count() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let request = request();
    let mut response = response(&request);
    sign(&mut response, &key);
    verify(&response, &request, &key).expect("exact approval lookup");
    for case in 0..3 {
        let mut changed = response.clone();
        let requirements = changed.prepared.revocation.as_mut().expect("requirements");
        match case {
            0 => requirements.target_device_ref = "device-d".into(),
            1 => requirements.required_approval_authority_ref = Some("other-authority".into()),
            _ => requirements.expected_revoked_session_count = Some(1),
        }
        sign(&mut changed, &key);
        assert_eq!(
            verify(&changed, &request, &key),
            Err(ContractError::Invalid),
            "case {case}"
        );
    }
}

#[test]
fn source_cancel_lookup_accepts_an_active_independent_uv_wait() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let prepared = prepared("device-b");
    let mut request = EndpointPreparedLookupRequestV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA.into(),
        request_id: "cancel-approval-uv".into(),
        operation_id: prepared.operation_id,
        expected_state_revision: 3,
        phase: EndpointPreparedLookupPhaseV1::Cancel,
        identity_exchange: identity_exchange(&actor("device-a", 'a')),
    };
    let mut value = response(&request);
    value.operation.state = ManagementOperationState::AwaitingApprovalUv;
    value.operation.webauthn_options = Some(options());
    sign(&mut value, &key);
    verify(&value, &request, &key).expect("source can cancel approval UV wait");
    request.identity_exchange = identity_exchange(&actor("device-b", 'b'));
    value.request_digest_sha256 =
        endpoint_prepared_lookup_request_digest(&request).expect("digest");
    value.actor_device_ref = "device-b".into();
    value.actor_session_ref = identity_evidence_from_exchange(&request.identity_exchange)
        .expect("identity")
        .assertion
        .session_ref
        .clone();
    sign(&mut value, &key);
    assert_eq!(verify(&value, &request, &key), Err(ContractError::Invalid));
}

fn options() -> WebAuthnOptionsV2 {
    WebAuthnOptionsV2 {
        attempt_id: "cancel-approval-attempt".into(),
        challenge: "Y2hhbGxlbmdl".into(),
        rp_id: "example.test".into(),
        origin: "https://example.test".into(),
        credential_id: "credential-c".into(),
        timeout_ms: 30_000,
        expires_at_epoch_s: 130,
        command_binding_sha256: "aa".repeat(32),
    }
}
