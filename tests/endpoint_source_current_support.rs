use crowsi_credential_authority_contracts::WebAuthnOptionsV2;

pub(crate) fn options() -> WebAuthnOptionsV2 {
    WebAuthnOptionsV2 {
        attempt_id: "cancel-target-attempt".into(),
        challenge: "Y2hhbGxlbmdl".into(),
        rp_id: "example.test".into(),
        origin: "https://example.test".into(),
        credential_id: "credential-a".into(),
        timeout_ms: 30_000,
        expires_at_epoch_s: 130,
        command_binding_sha256: "aa".repeat(32),
    }
}

pub(crate) fn advance(
    value: &mut ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
    now: u64,
) {
    value.assertion.nonce = format!("fresh-nonce-{now}");
    value.current_status.nonce = value.assertion.nonce.clone();
    value.assertion.issued_at_epoch_s = now;
    value.current_status.issued_at_epoch_s = now;
    value.assertion.expires_at_epoch_s = now + 30;
    value.current_status.expires_at_epoch_s = now + 30;
}
