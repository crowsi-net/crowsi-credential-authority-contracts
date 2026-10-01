use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    canonical_assertion_payload, canonical_current_status_payload,
};

use crate::endpoint_revocation_values::actor;

#[test]
fn identity_and_current_status_are_current_exact_and_use_distinct_pinned_keys() {
    let mut value = actor("device-a", 'a');
    value.assertion.device_posture.state = "compliant".into();
    value.current_status.device_posture.state = "compliant".into();
    let assertion_key = SigningKey::from_bytes(&[1_u8; 32]);
    let status_key = SigningKey::from_bytes(&[2_u8; 32]);
    value.assertion.key_id = "assertion-key".into();
    value.current_status.key_id = "status-key".into();
    value.assertion.signature = hex::encode(
        assertion_key
            .sign(&canonical_assertion_payload(&value.assertion))
            .to_bytes(),
    );
    value.current_status.signature = hex::encode(
        status_key
            .sign(&canonical_current_status_payload(&value.current_status))
            .to_bytes(),
    );
    let assertion_public = hex::encode(assertion_key.verifying_key().to_bytes());
    let status_public = hex::encode(status_key.verifying_key().to_bytes());
    let trust = EndpointIdentityTrustV2 {
        issuer: "ihat-authority",
        audience: "crowsi-management",
        assertion_key_id: "assertion-key",
        assertion_public_key_hex: &assertion_public,
        current_status_key_id: "status-key",
        current_status_public_key_hex: &status_public,
        now_epoch_s: 110,
    };
    verify_endpoint_identity_at(&value, &trust).expect("verified identity pair");
    let stale = EndpointIdentityTrustV2 {
        now_epoch_s: 130,
        ..trust
    };
    assert_eq!(
        verify_endpoint_identity_at(&value, &stale),
        Err(ContractError::Invalid)
    );
    let aliased = EndpointIdentityTrustV2 {
        current_status_key_id: "assertion-key",
        current_status_public_key_hex: &assertion_public,
        ..trust
    };
    assert_eq!(
        verify_endpoint_identity_at(&value, &aliased),
        Err(ContractError::Invalid)
    );
    value.current_status.session_ref = format!("sref_{}", "b".repeat(64));
    value.current_status.signature = hex::encode(
        status_key
            .sign(&canonical_current_status_payload(&value.current_status))
            .to_bytes(),
    );
    assert_eq!(
        verify_endpoint_identity_at(&value, &trust),
        Err(ContractError::Invalid)
    );
}
