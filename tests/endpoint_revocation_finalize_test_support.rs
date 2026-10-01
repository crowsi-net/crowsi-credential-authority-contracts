fn request() -> (
    EndpointRevocationFinalizeRequestV1,
    SignedAuthorityExchangeV1,
) {
    let envelope = accepted_source_envelope();
    let source_approve_request = envelope.browser_request.clone();
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange,
        prepared,
        revocation_ceremony: Some(ceremony),
        ..
    } = envelope.evidence
    else {
        unreachable!()
    };
    let mut final_revoke_exchange = final_exchange(&prepared, NOW);
    let execution_reservation_id = "66".repeat(32);
    let binding = ihat_identity_assertion_contracts::command_digest(&final_revoke_exchange.request)
        .expect("final command digest");
    let execution_reservation_token = ihat_identity_assertion_contracts::SignedEvidenceV1 {
        schema: ihat_identity_assertion_contracts::SIGNED_EVIDENCE_SCHEMA.into(),
        role: ihat_identity_assertion_contracts::VerificationRole::RevocationExecutionReservation,
        proof_id: execution_reservation_id.clone(),
        key_id: "reservation-root".into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 119,
        binding_sha256: binding,
        signature: "77".repeat(64),
    };
    final_revoke_exchange.request.evidence.push(
        ihat_identity_assertion_contracts::AuthorityEvidence::Signed(
            execution_reservation_token.clone(),
        ),
    );
    let value = EndpointRevocationFinalizeRequestV1 {
        schema: ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA.into(),
        request_id: "finalize-request-a".into(),
        operation_id: prepared.operation_id.clone(),
        expected_state_revision: 3,
        pre_final_state_revision: 2,
        reconcile_digest: "44".repeat(32),
        source_approve_request,
        pre_final_request_sha256: "55".repeat(32),
        accepted_identity_exchange: identity_exchange,
        execution_reservation_id,
        execution_reservation_token,
        final_revoke_exchange,
        prepared,
    };
    (value, ceremony.begin)
}

fn accepted_source_envelope() -> EndpointManagementEnvelopeV2 {
    let mut envelope = source_envelope("device-a");
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange, ..
    } = &mut envelope.evidence
    else {
        unreachable!()
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut identity_exchange.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.device_posture.state = "compliant".into();
    identity.current_status.device_posture.state = "compliant".into();
    envelope
}

include!("endpoint_revocation_finalize_projection_support.rs");
