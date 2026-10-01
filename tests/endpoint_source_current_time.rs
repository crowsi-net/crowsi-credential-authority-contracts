use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{ResponseOutcome, canonical_response};

use crate::endpoint_source_current_tests::source_approve;

#[test]
fn approval_rejects_stale_original_identity_but_accepts_new_same_context_identity() {
    let key = SigningKey::from_bytes(&[6_u8; 32]);
    let mut stale = source_approve("device-a", 'a', 100);
    let stale_exchange = identity(&mut stale);
    sign(stale_exchange, &key);
    assert_eq!(
        verify(stale_exchange, &key, 140),
        Err(ContractError::Invalid)
    );

    let mut current = source_approve("device-a", 'a', 140);
    let current_exchange = identity(&mut current);
    sign(current_exchange, &key);
    verify(current_exchange, &key, 145).expect("new same-context identity");
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&current).expect("wire"))
        .expect("new nonce does not replace selected UV context");
}

#[test]
fn approval_rejects_current_epoch_substitution() {
    let mut value = source_approve("device-a", 'a', 140);
    let exchange = identity(&mut value);
    let ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::IdentityEvidence(identity),
    } = &mut exchange.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.revocation_epochs.device += 1;
    identity.current_status.revocation_epochs.device += 1;
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(&value).expect("wire")),
        Err(ContractError::Invalid)
    );
}

fn identity(value: &mut EndpointManagementEnvelopeV2) -> &mut SignedAuthorityExchangeV1 {
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange, ..
    } = &mut value.evidence
    else {
        unreachable!()
    };
    identity_exchange
}

fn sign(value: &mut SignedAuthorityExchangeV1, key: &SigningKey) {
    value.response.key_id = "current-response-key".into();
    value.response.signature = hex::encode(
        key.sign(&canonical_response(&value.response).expect("canonical"))
            .to_bytes(),
    );
}

fn verify(
    value: &SignedAuthorityExchangeV1,
    key: &SigningKey,
    now: u64,
) -> Result<(), ContractError> {
    verify_authority_exchange_at(
        value,
        "issue_current_device_identity_evidence",
        1,
        "current-response-key",
        &hex::encode(key.verifying_key().to_bytes()),
        now,
    )
}
