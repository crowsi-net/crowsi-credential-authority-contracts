use crowsi_credential_authority_contracts::*;

use crate::endpoint_envelope::identity;

#[test]
fn prepared_operation_is_fresh_exact_and_cannot_be_recreated_with_the_same_identifier() {
    let identity = identity();
    let mut prepared = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: identity.assertion.session_ref.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: identity.assertion.nonce.clone(),
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
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    validate_endpoint_prepared_at(&prepared, &identity, 110).expect("fresh prepared");
    assert_eq!(
        validate_endpoint_prepared_at(&prepared, &identity, 130),
        Err(ContractError::Invalid)
    );
    let old_id = prepared.operation_id.clone();
    prepared.nonce = "new-operation-nonce".into();
    prepared.operation_id = endpoint_operation_id(&prepared).expect("new operation id");
    assert_ne!(prepared.operation_id, old_id);
    let mut substituted = prepared;
    substituted.source_identity_nonce = "other-identity-nonce".into();
    assert_eq!(
        validate_endpoint_prepared_at(&substituted, &identity, 110),
        Err(ContractError::Invalid)
    );
}
