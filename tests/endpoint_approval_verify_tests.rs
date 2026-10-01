use crowsi_credential_authority_contracts::*;
use ed25519_dalek::SigningKey;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, command_digest,
};

use crate::{
    endpoint_approval_verify_call::verify,
    endpoint_approval_verify_support::{PublicKeys, sign_fresh, sign_identity, sign_response},
    endpoint_management_values::{identity_exchange, uv_options},
    endpoint_revocation_values::actor,
    endpoint_source_current_tests::source_approve,
};

#[test]
fn approval_verifier_accepts_new_nonce_and_rejects_stale_current_or_generation_rollback() {
    let selected = actor("device-a", 'a');
    let mut envelope = source_approve("device-a", 'a', 140);
    let (prepared, finish, current, browser) = approval(&mut envelope);
    let mut selected_exchange = identity_exchange(&selected);
    let mut begin = uv_options(&selected, &prepared);
    align_begin(&mut begin, finish, browser);
    let assertion_key = SigningKey::from_bytes(&[1; 32]);
    let status_key = SigningKey::from_bytes(&[2; 32]);
    let fresh_key = SigningKey::from_bytes(&[3; 32]);
    let authority_key = SigningKey::from_bytes(&[4; 32]);
    sign_identity(&mut selected_exchange, &assertion_key, &status_key);
    sign_identity(current, &assertion_key, &status_key);
    sign_fresh(finish, &fresh_key);
    for exchange in [&mut selected_exchange, &mut begin, finish, current] {
        sign_response(exchange, &authority_key);
    }
    let public = PublicKeys {
        assertion: hex::encode(assertion_key.verifying_key().to_bytes()),
        status: hex::encode(status_key.verifying_key().to_bytes()),
        fresh: hex::encode(fresh_key.verifying_key().to_bytes()),
        authority: hex::encode(authority_key.verifying_key().to_bytes()),
    };
    verify(
        &selected_exchange,
        &begin,
        finish,
        current,
        &prepared,
        browser,
        &public,
    )
    .expect("selected UV plus submission-current identity");
    assert!(
        verify(
            &selected_exchange,
            &begin,
            finish,
            &selected_exchange,
            &prepared,
            browser,
            &public,
        )
        .is_err()
    );
    let mut rollback = current.clone();
    rollback.response.config_generation = 1;
    sign_response(&mut rollback, &authority_key);
    assert!(
        verify(
            &selected_exchange,
            &begin,
            finish,
            &rollback,
            &prepared,
            browser,
            &public,
        )
        .is_err()
    );
}

fn approval(
    value: &mut EndpointManagementEnvelopeV2,
) -> (
    EndpointPreparedOperationV2,
    &mut SignedAuthorityExchangeV1,
    &mut SignedAuthorityExchangeV1,
    &ManagementCommandV2,
) {
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange,
        prepared,
        finish_uv_exchange,
        ..
    } = &mut value.evidence
    else {
        unreachable!()
    };
    (
        prepared.clone(),
        finish_uv_exchange,
        identity_exchange,
        &value.browser_request.command,
    )
}

fn align_begin(
    begin: &mut SignedAuthorityExchangeV1,
    finish: &SignedAuthorityExchangeV1,
    browser: &ManagementCommandV2,
) {
    let fresh = fresh_uv_from_finish_exchange(finish, browser).expect("fresh");
    let AuthorityCommand::BeginFreshUserVerification(command) = &mut begin.request.command else {
        unreachable!()
    };
    command.credential_id.clone_from(&fresh.credential_id);
    let digest = command_digest(&begin.request).expect("digest");
    begin.response.command_digest.clone_from(&digest);
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut begin.response.outcome
    else {
        unreachable!()
    };
    options.attempt_id.clone_from(&fresh.attempt_id);
    options.credential_id.clone_from(&fresh.credential_id);
    options.challenge.clone_from(&fresh.challenge);
    options.expires_at_epoch_s = 220;
    options.command_binding_sha256 = digest;
}
