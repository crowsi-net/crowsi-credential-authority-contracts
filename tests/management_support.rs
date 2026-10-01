use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

pub fn signed_projection(now: u64) -> (ManagementProjectionV2, SigningKey) {
    let key = SigningKey::from_bytes(&[5_u8; 32]);
    let operation = ManagementOperationV2 {
        operation_id: "operation-a".into(),
        kind: ManagementOperationKind::DeviceTransfer,
        intent_digest_sha256: "aa".repeat(32),
        state: ManagementOperationState::AwaitingTarget,
        state_revision: 2,
        created_at_epoch_s: now,
        expires_at_epoch_s: now + 300,
        source_device_ref: "device-a".into(),
        scope: ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_source_device_revocation_epoch: 3,
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
    };
    let mut value = ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: "projection-a".into(),
        request_id: "request-a".into(),
        command_digest_sha256: "bb".repeat(32),
        issuer: "crowsi-credential-authority".into(),
        audience: "endpoint-device-a".into(),
        service_id: "service-a".into(),
        pairwise_subject: "pairwise-a".into(),
        opaque_account_ref: "owner-a".into(),
        current_device_ref: "device-a".into(),
        current_session_ref: format!("sref_{}", "a".repeat(64)),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 2,
        device_revocation_epoch: 3,
        session_revocation_epoch: 4,
        device_posture_state: "compliant".into(),
        device_posture_revision: 5,
        device_proof_key_ref: "device-proof:sha256:device-a".into(),
        snapshot_revision: 4,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 30,
        body: ManagementProjectionBodyV2::Operation { operation },
        key_id: "management-key".into(),
        signature: String::new(),
    };
    value.signature = hex::encode(
        key.sign(&canonical_management_projection(&value).expect("canonical"))
            .to_bytes(),
    );
    (value, key)
}

pub fn binding<'a>(
    value: &'a ManagementProjectionV2,
    device: &'a str,
) -> ManagementProjectionBinding<'a> {
    ManagementProjectionBinding {
        request_id: &value.request_id,
        command_digest_sha256: &value.command_digest_sha256,
        issuer: &value.issuer,
        audience: &value.audience,
        service_id: &value.service_id,
        pairwise_subject: &value.pairwise_subject,
        opaque_account_ref: &value.opaque_account_ref,
        current_device_ref: device,
        current_session_ref: &value.current_session_ref,
        subject_revocation_epoch: value.subject_revocation_epoch,
        service_revocation_epoch: value.service_revocation_epoch,
        device_revocation_epoch: value.device_revocation_epoch,
        session_revocation_epoch: value.session_revocation_epoch,
        device_posture_state: &value.device_posture_state,
        device_posture_revision: value.device_posture_revision,
        device_proof_key_ref: &value.device_proof_key_ref,
        minimum_snapshot_revision: value.snapshot_revision,
    }
}
