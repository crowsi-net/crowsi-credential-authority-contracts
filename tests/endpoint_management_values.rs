use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::*;

pub(crate) fn assertion(credential: &str) -> WebAuthnAssertionV2 {
    WebAuthnAssertionV2 {
        credential_id: credential.into(),
        client_data_json_base64url: "e30".into(),
        authenticator_data_base64url: "AA".into(),
        signature_der_base64url: "MA".into(),
    }
}

pub(crate) fn browser(request_id: &str, command: ManagementCommandV2) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: request_id.into(),
        command,
    }
}

pub(crate) fn exchange(
    request_id: &str,
    command: AuthorityCommand,
    evidence: Vec<AuthorityEvidence>,
    result: AuthorityResult,
    issued: u64,
) -> SignedAuthorityExchangeV1 {
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request_id.into(),
        command,
        evidence,
    };
    let digest = command_digest(&request).expect("digest");
    for evidence in &mut request.evidence {
        if let AuthorityEvidence::Signed(value) = evidence {
            value.binding_sha256.clone_from(&digest);
        }
    }
    let response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request_id.into(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: 2,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: issued + 30,
        outcome: ResponseOutcome::Committed { result },
        key_id: "authority-response-key".into(),
        signature: "66".repeat(64),
    };
    SignedAuthorityExchangeV1 { request, response }
}

pub(crate) fn identity_exchange(identity: &IdentityEvidenceMetadata) -> SignedAuthorityExchangeV1 {
    let proof_id = format!("session-sender-{}", identity.assertion.device_id);
    let command = AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
        IssueCurrentDeviceIdentityEvidenceCommand {
            service_id: identity.assertion.service_id.clone(),
            pairwise_subject: identity.assertion.pairwise_subject.clone(),
            device_id: identity.assertion.device_id.clone(),
            audience: identity.assertion.audience.clone(),
            identity_nonce: identity.assertion.nonce.clone(),
            ttl_seconds: 30,
            session_sender_key_fingerprint: "55".repeat(32),
            session_sender_proof_id: proof_id.clone(),
        },
    );
    let sender = AuthorityEvidence::Signed(SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id,
        key_id: "session-sender-key".into(),
        issued_at_epoch_s: identity.assertion.issued_at_epoch_s,
        expires_at_epoch_s: identity.assertion.expires_at_epoch_s,
        binding_sha256: "00".repeat(32),
        signature: "55".repeat(64),
    });
    exchange(
        &format!("current-identity-{}", identity.assertion.device_id),
        command,
        vec![sender],
        AuthorityResult::IdentityEvidence(identity.clone()),
        identity.assertion.issued_at_epoch_s,
    )
}

pub(crate) fn uv_options(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
) -> SignedAuthorityExchangeV1 {
    let epochs = &identity.assertion.revocation_epochs;
    let digest = endpoint_operation_digest(prepared).expect("operation digest");
    let command = AuthorityCommand::BeginFreshUserVerification(BeginFreshUvCommand {
        command_id: format!("options-{}", identity.assertion.device_id),
        credential_id: format!("credential-{}", identity.assertion.device_id),
        identity_nonce: identity.assertion.nonce.clone(),
        source_device_id: identity.assertion.device_id.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        session_ref: identity.assertion.session_ref.clone(),
        operation_digest_sha256: digest.clone(),
        subject_epoch: epochs.subject,
        service_epoch: epochs.service,
        device_epoch: epochs.device,
        session_epoch: epochs.session,
    });
    let result = FreshUvRequestOptions {
        attempt_id: format!("attempt-credential-{}", identity.assertion.device_id),
        challenge: "options-challenge".into(),
        rp_id: "example.test".into(),
        origin: "https://example.test".into(),
        credential_id: format!("credential-{}", identity.assertion.device_id),
        timeout_ms: 30_000,
        expires_at_epoch_s: 130,
        command_binding_sha256: digest,
    };
    let mut value = exchange(
        "options-request",
        command,
        vec![],
        AuthorityResult::FreshUvBegun(result),
        100,
    );
    let request_digest = command_digest(&value.request).expect("request digest");
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    options.command_binding_sha256 = request_digest;
    value
}
