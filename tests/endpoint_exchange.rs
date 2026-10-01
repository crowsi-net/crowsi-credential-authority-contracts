use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityRequestV1,
    AuthorityResponseV1, AuthorityResult, BeginFreshUvCommand, FreshUvRequestOptions,
    ResponseOutcome, canonical_response, command_digest,
};

pub(crate) fn exchange(request_id: &str) -> SignedAuthorityExchangeV1 {
    let request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request_id.into(),
        command: AuthorityCommand::BeginFreshUserVerification(BeginFreshUvCommand {
            command_id: "uv-command".into(),
            credential_id: "credential-a".into(),
            identity_nonce: "identity-nonce".into(),
            source_device_id: "device-a".into(),
            service_id: "service-a".into(),
            pairwise_subject: "psu_pairwise-a".into(),
            session_ref: format!("sref_{}", "a".repeat(64)),
            operation_digest_sha256: "aa".repeat(32),
            subject_epoch: 1,
            service_epoch: 1,
            device_epoch: 1,
            session_epoch: 1,
        }),
        evidence: vec![],
    };
    let response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request_id.into(),
        command_type: "begin_fresh_user_verification".into(),
        command_digest: command_digest(&request).expect("digest"),
        config_generation: 2,
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 130,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(FreshUvRequestOptions {
                attempt_id: "attempt-a".into(),
                challenge: "challenge-a".into(),
                rp_id: "example.test".into(),
                origin: "https://example.test".into(),
                credential_id: "credential-a".into(),
                timeout_ms: 30_000,
                expires_at_epoch_s: 130,
                command_binding_sha256: "aa".repeat(32),
            }),
        },
        key_id: "identity-response-key".into(),
        signature: "00".repeat(64),
    };
    SignedAuthorityExchangeV1 { request, response }
}

#[test]
fn authority_exchange_signature_key_generation_and_time_are_pinned() {
    let mut value = exchange("signed-request");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    value.response.key_id = "pinned-response-key".into();
    value.response.signature = hex::encode(
        key.sign(&canonical_response(&value.response).expect("canonical"))
            .to_bytes(),
    );
    let public = hex::encode(key.verifying_key().to_bytes());
    verify_authority_exchange_at(
        &value,
        "begin_fresh_user_verification",
        2,
        "pinned-response-key",
        &public,
        110,
    )
    .expect("verified exchange");
    for (generation, key_id, now) in [
        (3, "pinned-response-key", 110),
        (2, "other-key", 110),
        (2, "pinned-response-key", 130),
    ] {
        assert_eq!(
            verify_authority_exchange_at(
                &value,
                "begin_fresh_user_verification",
                generation,
                key_id,
                &public,
                now
            ),
            Err(ContractError::Invalid)
        );
    }
    value.response.signature = "00".repeat(64);
    assert_eq!(
        verify_authority_exchange_at(
            &value,
            "begin_fresh_user_verification",
            2,
            "pinned-response-key",
            &public,
            110
        ),
        Err(ContractError::Invalid)
    );
}

#[test]
fn authority_exchange_rejects_response_only_cross_request_and_context_substitution() {
    let valid = exchange("identity-request-a");
    validate_authority_exchange(&valid, "begin_fresh_user_verification").expect("exact pair");
    for case in 0..4 {
        let mut value = valid.clone();
        match case {
            0 => value.response.request_id = "identity-request-b".into(),
            1 => value.response.command_type = "reconcile".into(),
            2 => value.response.command_digest = "bb".repeat(32),
            _ => value.response.config_generation = 0,
        }
        assert_eq!(
            validate_authority_exchange(&value, "begin_fresh_user_verification"),
            Err(ContractError::Invalid),
            "case {case}"
        );
    }
    let mut cross = exchange("identity-request-b");
    cross.request = valid.request.clone();
    assert_eq!(
        validate_authority_exchange(&cross, "begin_fresh_user_verification"),
        Err(ContractError::Invalid)
    );
    assert_eq!(
        validate_authority_exchange(&valid, "reconcile"),
        Err(ContractError::Invalid)
    );
    for missing in ["request", "response"] {
        let mut value = serde_json::to_value(&valid).expect("json");
        value.as_object_mut().expect("object").remove(missing);
        assert!(serde_json::from_value::<SignedAuthorityExchangeV1>(value).is_err());
    }
}
