fn cancel_envelope() -> EndpointManagementEnvelopeV2 {
    let source = source_envelope("device-a");
    let EndpointManagementEvidenceV2::SourceApprove {
        mut identity_exchange,
        prepared,
        ..
    } = source.evidence
    else {
        unreachable!()
    };
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::IdentityEvidence(identity),
    } = &mut identity_exchange.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.device_posture.state = "compliant".into();
    identity.current_status.device_posture.state = "compliant".into();
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser(
            "cancel-recovery",
            ManagementCommandV2::Cancel {
                operation_id: prepared.operation_id.clone(),
                expected_state_revision: 2,
            },
        ),
        evidence: EndpointManagementEvidenceV2::Cancel {
            identity_exchange,
            prepared,
        },
    }
}

fn cancel_projection(
    envelope: &EndpointManagementEnvelopeV2,
    key: &SigningKey,
) -> ManagementProjectionV2 {
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange,
        prepared,
    } = &envelope.evidence
    else {
        unreachable!()
    };
    let identity = identity_evidence_from_exchange(identity_exchange).expect("identity");
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let (mut value, _) = signed_projection(NOW);
    bind_projection(&mut value, envelope, prepared, assertion);
    value.subject_revocation_epoch = epochs.subject;
    value.service_revocation_epoch = epochs.service;
    value.device_revocation_epoch = epochs.device;
    value.session_revocation_epoch = epochs.session;
    let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
        unreachable!()
    };
    operation.operation_id.clone_from(&prepared.operation_id);
    operation.kind = ManagementOperationKind::DeviceRevocation;
    operation
        .intent_digest_sha256
        .clone_from(&prepared.origin_command_digest_sha256);
    operation.state = ManagementOperationState::Cancelled;
    operation.state_revision = 3;
    operation.created_at_epoch_s = prepared.issued_at_epoch_s;
    operation.expires_at_epoch_s = prepared.expires_at_epoch_s;
    operation
        .source_device_ref
        .clone_from(&prepared.source_device_ref);
    operation.scope = ManagementOperationScopeV2::DeviceRevocation {
        target_device_ref: "device-a".into(),
        expected_device_revocation_epoch: 1,
        revokes_session_refs: vec!["session-a".into(), "session-b".into()],
        rotates_credential_refs: Vec::new(),
        preserves_device_refs: Vec::new(),
    };
    operation.actor = ActorRequirementV2 {
        role: RequiredActorRole::NoActor,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    };
    operation.reason = Some(ManagementReasonCode::OperationCancelled);
    operation.reconcile_digest = None;
    resign(&mut value, key);
    value
}

fn bind_projection(
    value: &mut ManagementProjectionV2,
    envelope: &EndpointManagementEnvelopeV2,
    prepared: &EndpointPreparedOperationV2,
    assertion: &ihat_identity_assertion_contracts::DeviceIdentityAssertionV1,
) {
    value
        .request_id
        .clone_from(&envelope.browser_request.request_id);
    value.command_digest_sha256 =
        management_command_digest(&envelope.browser_request).expect("command digest");
    value.service_id.clone_from(&assertion.service_id);
    value
        .pairwise_subject
        .clone_from(&assertion.pairwise_subject);
    value
        .opaque_account_ref
        .clone_from(&prepared.opaque_owner_ref);
    value.current_device_ref.clone_from(&assertion.device_id);
    value.current_session_ref.clone_from(&assertion.session_ref);
    value
        .device_posture_state
        .clone_from(&assertion.device_posture.state);
    value.device_posture_revision = assertion.device_posture.revision;
    value
        .device_proof_key_ref
        .clone_from(&assertion.device_proof_key_ref);
}

fn verify(
    value: &ManagementProjectionV2,
    envelope: &EndpointManagementEnvelopeV2,
    key: &SigningKey,
) -> Result<(), ContractError> {
    verify_endpoint_historic_cancel_projection_at(
        value,
        envelope,
        "device-a",
        &EndpointHistoricCancelProjectionTrustV1 {
            issuer: "crowsi-credential-authority",
            audience: "endpoint-device-a",
            key_id: "management-key",
            public_key_hex: &hex::encode(key.verifying_key().to_bytes()),
            minimum_snapshot_revision: 1,
            now_epoch_s: NOW + 1,
        },
    )
}

fn resign(value: &mut ManagementProjectionV2, key: &SigningKey) {
    value.signature = hex::encode(
        key.sign(&canonical_management_projection(value).expect("canonical"))
            .to_bytes(),
    );
}
