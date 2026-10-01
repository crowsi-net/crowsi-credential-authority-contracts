use crate::management_support::{binding, signed_projection};
use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, VerifyingKey};

#[test]
fn operation_state_and_actor_metadata_are_closed() {
    for state in [
        "awaiting_source_uv",
        "awaiting_target",
        "awaiting_target_uv",
        "awaiting_independent_approval",
        "awaiting_approval_uv",
        "awaiting_revocation_final",
        "executing",
        "unknown",
        "completed",
        "rejected",
        "cancelled",
        "expired",
    ] {
        serde_json::from_value::<ManagementOperationState>(state.into()).expect("closed state");
    }
    assert!(serde_json::from_value::<ManagementOperationState>("caller_defined".into()).is_err());
    let (value, _) = signed_projection(1_700_000_000);
    let wire = String::from_utf8(serde_json::to_vec(&value).expect("json")).expect("utf8");
    for field in [
        "current_device_ref",
        "required_actor_device_ref",
        "excluded_actor_device_refs",
        "expected_source_device_revocation_epoch",
    ] {
        assert!(wire.contains(field), "{field}");
    }
}

#[test]
fn cross_device_revocation_requires_a_distinct_signed_actor() {
    let now = 1_700_000_000;
    let (mut value, key) = signed_projection(now);
    let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
        panic!("operation")
    };
    operation.kind = ManagementOperationKind::DeviceRevocation;
    operation.state = ManagementOperationState::AwaitingIndependentApproval;
    operation.scope = ManagementOperationScopeV2::DeviceRevocation {
        target_device_ref: "device-b".into(),
        expected_device_revocation_epoch: 8,
        revokes_session_refs: vec!["session-b".into()],
        rotates_credential_refs: vec!["credential-a".into()],
        preserves_device_refs: vec!["device-a".into()],
    };
    operation.actor = ActorRequirementV2 {
        role: RequiredActorRole::IndependentApproval,
        required_actor_device_ref: Some("device-c".into()),
        required_approval_authority_ref: None,
        excluded_actor_device_refs: vec!["device-a".into(), "device-b".into()],
    };
    resign(&mut value, &key);
    let public = hex::encode(VerifyingKey::from(&key).to_bytes());
    verify_management_projection_at(
        &value,
        &binding(&value, "device-a"),
        "management-key",
        &public,
        now + 1,
    )
    .expect("distinct C approval");
    let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
        panic!("operation")
    };
    operation.actor.required_actor_device_ref = Some("device-a".into());
    resign(&mut value, &key);
    assert_eq!(
        verify_management_projection_at(
            &value,
            &binding(&value, "device-a"),
            "management-key",
            &public,
            now + 1
        ),
        Err(ContractError::Invalid)
    );
}

fn resign(value: &mut ManagementProjectionV2, key: &ed25519_dalek::SigningKey) {
    value.signature = hex::encode(
        key.sign(&canonical_management_projection(value).expect("canonical"))
            .to_bytes(),
    );
}
