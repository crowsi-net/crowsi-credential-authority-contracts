use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::{endpoint_envelope::identity, endpoint_revocation_values::fresh};

pub(crate) fn fixture() -> (
    ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
    EndpointPreparedOperationV2,
    SignedTargetDeviceProofV2,
) {
    let mut identity = identity();
    identity.assertion.device_id = "device-b".into();
    identity.current_status.device_id = "device-b".into();
    identity.assertion.device_proof_key_ref = "proof-b".into();
    identity.current_status.device_proof_key_ref = "proof-b".into();
    let mut prepared = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: format!("sref_{}", "a".repeat(64)),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: "identity-nonce".into(),
        nonce: "prepared-nonce".into(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 130,
        intent: ManagementIntentV2::DeviceTransfer {
            service_id: "service-a".into(),
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_snapshot_revision: 1,
            nonce: "intent-nonce".into(),
        },
        revocation: None,
    };
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let proof = SignedTargetDeviceProofV2 {
        binding: TargetDeviceProofBindingV2 {
            schema: "crowsi://identity/target-device-key-proof/v2".into(),
            owner_ref: "owner-a".into(),
            service_id: "service-a".into(),
            pairwise_subject: identity.assertion.pairwise_subject.clone(),
            operation_id: prepared.operation_id.clone(),
            challenge_digest_sha256: endpoint_operation_digest(&prepared).expect("digest"),
            source_device_ref: "device-a".into(),
            target_device_ref: "device-b".into(),
            device_proof_key_ref: "proof-b".into(),
            custody_revision: "cng-revision-1".into(),
            status_nonce: identity.current_status.nonce.clone(),
            issued_at_epoch_s: 100,
            expires_at_epoch_s: 130,
            nonce: "prepared-nonce".into(),
            key_id: "proof-b".into(),
        },
        signature_hex: "00".repeat(64),
    };
    (identity, prepared, proof)
}

#[test]
fn target_proof_signature_key_time_custody_revision_and_nonce_are_exact() {
    let (identity, prepared, mut value) = fixture();
    let fresh = fresh(&identity, &prepared, "target-proof-uv", "credential-b");
    value.binding.expires_at_epoch_s = fresh.expires_at_epoch_s;
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    value.signature_hex = hex::encode(
        key.sign(&target_device_proof_digest(&value.binding).expect("digest"))
            .to_bytes(),
    );
    let public = hex::encode(key.verifying_key().to_bytes());
    verify_target_device_proof_at(
        &identity, &prepared, &fresh, &value, "proof-b", &public, 110,
    )
    .expect("current exact proof");
    assert_eq!(
        verify_target_device_proof_at(
            &identity, &prepared, &fresh, &value, "proof-b", &public, 120
        ),
        Err(ContractError::Invalid)
    );
    assert_eq!(
        verify_target_device_proof_at(
            &identity,
            &prepared,
            &fresh,
            &value,
            "other-key",
            &public,
            110
        ),
        Err(ContractError::Invalid)
    );
    let mut substituted = value.clone();
    substituted.binding.custody_revision = "other-revision".into();
    assert_eq!(
        verify_target_device_proof_at(
            &identity,
            &prepared,
            &fresh,
            &substituted,
            "proof-b",
            &public,
            110
        ),
        Err(ContractError::Invalid)
    );
    substituted = value;
    substituted.binding.nonce = "other-nonce".into();
    assert_eq!(
        verify_target_device_proof_at(
            &identity,
            &prepared,
            &fresh,
            &substituted,
            "proof-b",
            &public,
            110
        ),
        Err(ContractError::Invalid)
    );
}

#[test]
fn target_proof_every_actor_scope_time_key_and_signature_field_is_closed() {
    let (identity, prepared, valid) = fixture();
    validate_target_device_proof_context(&identity, &prepared, &valid).expect("valid context");
    for case in 0..8 {
        let mut value = valid.clone();
        match case {
            0 => value.binding.challenge_digest_sha256 = "bb".repeat(32),
            1 => value.binding.owner_ref = "owner-b".into(),
            2 => value.binding.source_device_ref = "device-c".into(),
            3 => value.binding.expires_at_epoch_s = value.binding.issued_at_epoch_s + 61,
            4 => value.binding.nonce.clear(),
            5 => value.binding.key_id = "other-key".into(),
            6 => value.binding.custody_revision.clear(),
            _ => value.signature_hex = "00".repeat(63),
        }
        assert_eq!(
            validate_target_device_proof_context(&identity, &prepared, &value),
            Err(ContractError::Invalid),
            "case {case}"
        );
    }
}
