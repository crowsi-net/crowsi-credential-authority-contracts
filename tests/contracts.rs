use crowsi_credential_authority_contracts::{
    ContractError, OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1, OwnerRecoveryCustodyReceiptV1,
    OwnerRecoveryCustodyStateV1, TargetDeviceProofBindingV2, target_device_proof_digest,
};

#[test]
fn target_proof_is_closed_and_domain_separated() {
    let mut value = TargetDeviceProofBindingV2 {
        schema: "crowsi://identity/target-device-key-proof/v2".into(),
        owner_ref: "psa_owner_credential_scope_01".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "psu_pairwise_subject_01".into(),
        operation_id: "operation:1".into(),
        challenge_digest_sha256: format!("sha256:{}", "a".repeat(64)),
        source_device_ref: "device:a".into(),
        target_device_ref: "device:b".into(),
        device_proof_key_ref: "proof:b".into(),
        custody_revision: "cng-revision-1".into(),
        status_nonce: "status:1".into(),
        issued_at_epoch_s: 1,
        expires_at_epoch_s: 2,
        nonce: "nonce:1".into(),
        key_id: "key:1".into(),
    };
    let first = target_device_proof_digest(&value).expect("digest");
    value.custody_revision = "cng-revision-2".into();
    assert_ne!(
        first,
        target_device_proof_digest(&value).expect("changed custody")
    );
    value.custody_revision = "cng-revision-1".into();
    value.target_device_ref = "device:c".into();
    assert_ne!(first, target_device_proof_digest(&value).expect("changed"));
    value.schema = "wrong".into();
    assert_eq!(
        target_device_proof_digest(&value),
        Err(ContractError::Invalid)
    );
}

#[test]
fn owner_recovery_receipt_exposes_proof_but_no_mnemonic_material() {
    let receipt = OwnerRecoveryCustodyReceiptV1 {
        schema: OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1.into(),
        recovery_id: "recovery:1".into(),
        subject_ref: "owner:1".into(),
        custody_provider_ref: "crowsi:owner-recovery".into(),
        root_fingerprint_sha256: format!("sha256:{}", "a".repeat(64)),
        key_revision: 1,
        state: OwnerRecoveryCustodyStateV1::Verified,
        observed_at_epoch_s: 1,
    };
    receipt.validate().expect("public custody receipt");
    let encoded = serde_json::to_value(&receipt).expect("serialize");
    assert!(encoded.get("mnemonic").is_none());
    assert!(encoded.get("seed").is_none());
    assert!(encoded.get("private_key").is_none());
    let mut invalid = receipt;
    invalid.root_fingerprint_sha256 = "sha256:bad".into();
    assert_eq!(invalid.validate(), Err(ContractError::Invalid));
}
