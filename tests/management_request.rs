use crowsi_credential_authority_contracts::*;

#[test]
fn every_browser_command_is_closed_and_contains_no_signed_identity_evidence() {
    let commands = vec![
        ManagementCommandV2::Snapshot {
            service_id: "service-a".into(),
        },
        ManagementCommandV2::SourceOptions {
            intent: transfer_intent(),
        },
        ManagementCommandV2::SourceApprove {
            operation_id: "operation-a".into(),
            expected_state_revision: 1,
            attempt_id: "attempt-a".into(),
            assertion: assertion(),
        },
        ManagementCommandV2::PendingList {
            service_id: "service-a".into(),
        },
        ManagementCommandV2::TargetOptions {
            operation_id: "operation-a".into(),
            expected_state_revision: 2,
        },
        ManagementCommandV2::TargetApprove {
            operation_id: "operation-a".into(),
            expected_state_revision: 3,
            attempt_id: "attempt-b".into(),
            assertion: assertion(),
        },
        ManagementCommandV2::ApprovalOptions {
            operation_id: "operation-a".into(),
            expected_state_revision: 2,
        },
        ManagementCommandV2::ApproveRevocation {
            operation_id: "operation-a".into(),
            expected_state_revision: 3,
            attempt_id: "attempt-c".into(),
            assertion: assertion(),
        },
        ManagementCommandV2::Cancel {
            operation_id: "operation-a".into(),
            expected_state_revision: 2,
        },
        ManagementCommandV2::Reconcile {
            operation_id: "operation-a".into(),
            expected_state_revision: 4,
            reconcile_digest: "aa".repeat(32),
        },
    ];
    for command in commands {
        let request = ManagementRequestV2 {
            schema: MANAGEMENT_REQUEST_SCHEMA.into(),
            request_id: "request-a".into(),
            command,
        };
        let wire = serde_json::to_vec(&request).expect("encode");
        let decoded = decode_management_request_strict(&wire).expect("closed request");
        assert_eq!(decoded, request);
        let text = String::from_utf8(wire).expect("utf8");
        for forbidden in [
            "source_assertion",
            "current_status",
            "fresh_uv",
            "target_proof",
            "private_key",
            "account_id",
            "session_id",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
}

#[test]
fn caller_cannot_relay_another_devices_actor_or_proof_fields() {
    let request = ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "request-a".into(),
        command: ManagementCommandV2::TargetApprove {
            operation_id: "operation-a".into(),
            expected_state_revision: 3,
            attempt_id: "attempt-b".into(),
            assertion: assertion(),
        },
    };
    let mut value = serde_json::to_value(request).expect("json");
    let command = value["command"].as_object_mut().expect("command");
    command.insert("actor_device_ref".into(), "device-b".into());
    command.insert("target_proof".into(), "caller-proof".into());
    assert_eq!(
        decode_management_request_strict(&serde_json::to_vec(&value).expect("json")),
        Err(ContractError::Invalid)
    );
}

#[test]
fn management_command_digest_binds_schema_request_id_and_closed_command() {
    let request = ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "request-a".into(),
        command: ManagementCommandV2::Snapshot {
            service_id: "service-a".into(),
        },
    };
    let digest = management_command_digest(&request).expect("digest");
    assert_eq!(digest.len(), 64);
    let mut substituted = request.clone();
    substituted.request_id = "request-b".into();
    assert_ne!(
        digest,
        management_command_digest(&substituted).expect("digest")
    );
    substituted = request.clone();
    substituted.command = ManagementCommandV2::PendingList {
        service_id: "service-a".into(),
    };
    assert_ne!(
        digest,
        management_command_digest(&substituted).expect("digest")
    );
}

fn transfer_intent() -> ManagementIntentV2 {
    ManagementIntentV2::DeviceTransfer {
        service_id: "service-a".into(),
        target_device_ref: "device-b".into(),
        credential_refs: vec!["credential-a".into()],
        expected_snapshot_revision: 4,
        nonce: "nonce-a".into(),
    }
}

fn assertion() -> WebAuthnAssertionV2 {
    WebAuthnAssertionV2 {
        credential_id: "credential-a".into(),
        client_data_json_base64url: "e30".into(),
        authenticator_data_base64url: "AA".into(),
        signature_der_base64url: "MA".into(),
    }
}
