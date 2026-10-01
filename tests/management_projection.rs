use crowsi_credential_authority_contracts::*;
use ed25519_dalek::VerifyingKey;

use crate::management_support::{binding, signed_projection};

#[test]
fn authority_signature_binds_current_device_actor_state_and_scope() {
    let now = 1_700_000_000;
    let (value, key) = signed_projection(now);
    let public = hex::encode(VerifyingKey::from(&key).to_bytes());
    verify_management_projection_at(
        &value,
        &binding(&value, "device-a"),
        "management-key",
        &public,
        now + 1,
    )
    .expect("valid projection");
    let mut tampered = value.clone();
    if let ManagementProjectionBodyV2::Operation { operation } = &mut tampered.body {
        operation.actor.required_actor_device_ref = Some("device-c".into());
    }
    assert_eq!(
        verify_management_projection_at(
            &tampered,
            &binding(&tampered, "device-a"),
            "management-key",
            &public,
            now + 1
        ),
        Err(ContractError::Invalid)
    );
    assert_eq!(
        verify_management_projection_at(
            &value,
            &binding(&value, "device-b"),
            "management-key",
            &public,
            now + 1
        ),
        Err(ContractError::Invalid)
    );
    assert_eq!(
        verify_management_projection_at(
            &value,
            &binding(&value, "device-a"),
            "management-key",
            &public,
            now + 30
        ),
        Err(ContractError::Invalid)
    );
}

#[test]
fn projection_decoder_rejects_unknown_trailing_and_oversize_documents() {
    let (value, _) = signed_projection(1_700_000_000);
    let mut json = serde_json::to_value(&value).expect("json");
    json.as_object_mut()
        .expect("object")
        .insert("unknown".into(), true.into());
    assert_eq!(
        decode_management_projection_strict(&serde_json::to_vec(&json).expect("json")),
        Err(ContractError::Invalid)
    );
    let mut trailing = serde_json::to_vec(&value).expect("json");
    trailing.extend_from_slice(b" {}");
    assert_eq!(
        decode_management_projection_strict(&trailing),
        Err(ContractError::Invalid)
    );
    assert_eq!(
        decode_management_projection_strict(&vec![b' '; MAX_MANAGEMENT_WIRE_BYTES + 1]),
        Err(ContractError::Invalid)
    );
}

#[test]
// E2E-15: every management response is bound to the exact request and actor context.
fn request_account_session_and_epochs_are_exact_signed_bindings() {
    let now = 1_700_000_000;
    let (value, key) = signed_projection(now);
    let public = hex::encode(VerifyingKey::from(&key).to_bytes());
    let mut expected = binding(&value, "device-a");
    expected.request_id = "request-substituted";
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.opaque_account_ref = "owner-substituted";
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.current_session_ref = "sref_substituted";
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.subject_revocation_epoch += 1;
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.device_revocation_epoch += 1;
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.session_revocation_epoch += 1;
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.device_posture_state = "revoked";
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.device_posture_revision += 1;
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
    let mut expected = binding(&value, "device-a");
    expected.device_proof_key_ref = "device-proof:sha256:substituted";
    assert_eq!(
        verify_management_projection_at(&value, &expected, "management-key", &public, now + 1),
        Err(ContractError::Invalid)
    );
}
