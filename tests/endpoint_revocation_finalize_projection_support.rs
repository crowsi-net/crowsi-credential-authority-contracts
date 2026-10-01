fn projection(
    request: &EndpointRevocationFinalizeRequestV1,
    key: &SigningKey,
) -> ManagementProjectionV2 {
    let (mut value, _) = signed_projection(NOW);
    value
        .request_id
        .clone_from(&request.source_approve_request.request_id);
    value.command_digest_sha256 =
        management_command_digest(&request.source_approve_request).expect("digest");
    value.service_id = "service-a".into();
    value
        .pairwise_subject
        .clone_from(&request.prepared.pairwise_subject);
    value
        .opaque_account_ref
        .clone_from(&request.prepared.opaque_owner_ref);
    value
        .current_device_ref
        .clone_from(&request.prepared.source_device_ref);
    value
        .current_session_ref
        .clone_from(&request.prepared.source_session_ref);
    let identity = identity_evidence_from_exchange(&request.accepted_identity_exchange)
        .expect("accepted identity");
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    value.subject_revocation_epoch = epochs.subject;
    value.service_revocation_epoch = epochs.service;
    value.device_revocation_epoch = epochs.device;
    value.session_revocation_epoch = epochs.session;
    value
        .device_posture_state
        .clone_from(&assertion.device_posture.state);
    value.device_posture_revision = assertion.device_posture.revision;
    value
        .device_proof_key_ref
        .clone_from(&assertion.device_proof_key_ref);
    let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
        unreachable!()
    };
    operation.operation_id.clone_from(&request.operation_id);
    operation.kind = ManagementOperationKind::DeviceRevocation;
    operation
        .intent_digest_sha256
        .clone_from(&request.prepared.origin_command_digest_sha256);
    operation.state = ManagementOperationState::Unknown;
    operation.state_revision = request.expected_state_revision + 2;
    operation.created_at_epoch_s = request.prepared.issued_at_epoch_s;
    operation.expires_at_epoch_s = request.prepared.expires_at_epoch_s;
    operation
        .source_device_ref
        .clone_from(&request.prepared.source_device_ref);
    operation.scope = ManagementOperationScopeV2::DeviceRevocation {
        target_device_ref: "device-a".into(),
        expected_device_revocation_epoch: 1,
        revokes_session_refs: vec!["session-a".into(), "session-b".into()],
        rotates_credential_refs: vec![],
        preserves_device_refs: vec![],
    };
    operation.actor = ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: vec![],
    };
    operation.reason = Some(ManagementReasonCode::ProviderOutcomeUnknown);
    operation.reconcile_digest = Some(request.reconcile_digest.clone());
    resign(&mut value, key);
    value
}

fn verify(
    value: &ManagementProjectionV2,
    request: &EndpointRevocationFinalizeRequestV1,
    key: &SigningKey,
) -> Result<(), ContractError> {
    verify_endpoint_revocation_finalize_projection_at(
        value,
        request,
        "device-a",
        &EndpointRevocationFinalizeProjectionTrustV1 {
            issuer: "crowsi-credential-authority",
            audience: "endpoint-device-a",
            key_id: "management-key",
            public_key_hex: &hex::encode(key.verifying_key().to_bytes()),
            minimum_snapshot_revision: 1,
            now_epoch_s: NOW + 1,
        },
    )
}

fn pre_final_projection(
    envelope: &EndpointManagementEnvelopeV2,
    key: &SigningKey,
    issued_at: u64,
) -> ManagementProjectionV2 {
    let (request, _) = request();
    let mut value = projection(&request, key);
    let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
        unreachable!()
    };
    operation.state = ManagementOperationState::AwaitingRevocationFinal;
    operation.state_revision = 2;
    operation.reason = None;
    operation.reconcile_digest = Some("44".repeat(32));
    value
        .request_id
        .clone_from(&envelope.browser_request.request_id);
    value.command_digest_sha256 =
        management_command_digest(&envelope.browser_request).expect("digest");
    value.issued_at_epoch_s = issued_at;
    value.expires_at_epoch_s = issued_at + 30;
    resign(&mut value, key);
    value
}

fn verify_pre_final(
    value: &ManagementProjectionV2,
    envelope: &EndpointManagementEnvelopeV2,
    key: &SigningKey,
    now: u64,
) -> Result<(), ContractError> {
    verify_endpoint_revocation_pre_final_projection_at(
        value,
        envelope,
        "device-a",
        &EndpointRevocationPreFinalProjectionTrustV1 {
            issuer: "crowsi-credential-authority",
            audience: "endpoint-device-a",
            key_id: "management-key",
            public_key_hex: &hex::encode(key.verifying_key().to_bytes()),
            minimum_snapshot_revision: 1,
            now_epoch_s: now,
        },
    )
}

fn resign(value: &mut ManagementProjectionV2, key: &SigningKey) {
    value.signature = hex::encode(
        key.sign(&canonical_management_projection(value).expect("canonical"))
            .to_bytes(),
    );
}
