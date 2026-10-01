use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::canonical_fresh_uv;

use crate::endpoint_revocation_support::source_envelope;

#[test]
fn fresh_uv_signature_time_key_actor_operation_and_account_are_exact() {
    let value = source_envelope("device-b");
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange,
        prepared,
        finish_uv_exchange,
        ..
    } = value.evidence
    else {
        unreachable!()
    };
    let identity = identity_evidence_from_exchange(&identity_exchange)
        .expect("identity exchange")
        .clone();
    let mut fresh_uv =
        fresh_uv_from_finish_exchange(&finish_uv_exchange, &value.browser_request.command)
            .expect("finish exchange")
            .clone();
    let key = SigningKey::from_bytes(&[8_u8; 32]);
    fresh_uv.key_id = "pinned-uv-key".into();
    fresh_uv.signature = hex::encode(
        key.sign(&canonical_fresh_uv(&fresh_uv).expect("canonical"))
            .to_bytes(),
    );
    let public = hex::encode(key.verifying_key().to_bytes());
    let command = value.browser_request.command;
    let trust = EndpointFreshUvTrustV2 {
        account_binding_sha256: &fresh_uv.account_binding_sha256,
        key_id: "pinned-uv-key",
        public_key_hex: &public,
        now_epoch_s: 110,
    };
    verify_endpoint_fresh_uv_at(&identity, &prepared, &fresh_uv, &command, &trust)
        .expect("verified UV");
    let mut refreshed = identity.clone();
    refreshed.assertion.nonce = "fresh-current-identity-nonce".into();
    refreshed.current_status.nonce = refreshed.assertion.nonce.clone();
    verify_endpoint_fresh_uv_at(&refreshed, &prepared, &fresh_uv, &command, &trust)
        .expect("fresh current identity may have a new nonce");
    let wrong_account = EndpointFreshUvTrustV2 {
        account_binding_sha256: &"99".repeat(32),
        key_id: "pinned-uv-key",
        public_key_hex: &public,
        now_epoch_s: 110,
    };
    assert_eq!(
        verify_endpoint_fresh_uv_at(&identity, &prepared, &fresh_uv, &command, &wrong_account),
        Err(ContractError::Invalid)
    );
    let stale = EndpointFreshUvTrustV2 {
        account_binding_sha256: &fresh_uv.account_binding_sha256,
        key_id: "pinned-uv-key",
        public_key_hex: &public,
        now_epoch_s: 120,
    };
    assert_eq!(
        verify_endpoint_fresh_uv_at(&identity, &prepared, &fresh_uv, &command, &stale),
        Err(ContractError::Invalid)
    );
    fresh_uv.signature = "00".repeat(64);
    assert_eq!(
        verify_endpoint_fresh_uv_at(&identity, &prepared, &fresh_uv, &command, &trust),
        Err(ContractError::Invalid)
    );
}
