use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{
    CurrentDeviceStatusV1, DeviceIdentityAssertionV1, DevicePostureV1, IdentityEvidenceMetadata,
    RevocationEpochsV1,
};

#[test]
fn passive_envelope_is_closed_and_command_phase_mismatch_is_rejected() {
    let request = ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "request-a".into(),
        command: ManagementCommandV2::Snapshot {
            service_id: "service-a".into(),
        },
    };
    let identity = identity();
    let value = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: request,
        evidence: EndpointManagementEvidenceV2::Passive {
            identity_exchange: crate::endpoint_management_values::identity_exchange(&identity),
        },
    };
    let wire = serde_json::to_vec(&value).expect("wire");
    assert_eq!(
        decode_endpoint_management_envelope_strict(&wire),
        Ok(value.clone())
    );
    let mut substituted = value;
    substituted.browser_request.command = ManagementCommandV2::SourceOptions {
        intent: ManagementIntentV2::DeviceTransfer {
            service_id: "service-a".into(),
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_snapshot_revision: 1,
            nonce: "intent-nonce".into(),
        },
    };
    assert_eq!(
        decode_endpoint_management_envelope_strict(
            &serde_json::to_vec(&substituted).expect("wire")
        ),
        Err(ContractError::Invalid)
    );
}

#[test]
fn prepared_operation_digest_binds_source_origin_and_nonce() {
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: format!("sref_{}", "a".repeat(64)),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: "identity-nonce".into(),
        nonce: "operation-nonce".into(),
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
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    let digest = endpoint_operation_digest(&value).expect("digest");
    let mut substituted = value;
    substituted.source_device_ref = "device-b".into();
    assert_ne!(
        digest,
        endpoint_operation_digest(&substituted).expect("digest")
    );
}

pub(crate) fn identity() -> IdentityEvidenceMetadata {
    let posture = DevicePostureV1 {
        state: "healthy".into(),
        revision: 1,
    };
    let epochs = RevocationEpochsV1 {
        subject: 1,
        service: 1,
        device: 1,
        session: 1,
    };
    let assertion = DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: "ihat-authority".into(),
        audience: "crowsi-management".into(),
        service_id: "service-a".into(),
        pairwise_subject: "psu_pairwise-a".into(),
        device_id: "device-a".into(),
        device_proof_key_ref: "proof-a".into(),
        session_ref: format!("sref_{}", "a".repeat(64)),
        device_posture: posture.clone(),
        revocation_epochs: epochs.clone(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 130,
        nonce: "identity-nonce".into(),
        key_id: "identity-key".into(),
        signature: "00".repeat(64),
    };
    let status = CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: assertion.issuer.clone(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        device_id: assertion.device_id.clone(),
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        session_ref: assertion.session_ref.clone(),
        device_posture: posture,
        revocation_epochs: epochs,
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 130,
        nonce: assertion.nonce.clone(),
        key_id: "status-key".into(),
        signature: "11".repeat(64),
    };
    IdentityEvidenceMetadata {
        assertion,
        current_status: status,
    }
}
