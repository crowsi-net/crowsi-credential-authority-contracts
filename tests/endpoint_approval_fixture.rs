use crowsi_credential_authority_contracts::*;
use ed25519_dalek::SigningKey;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, command_digest,
};

use crate::{
    endpoint_approval_verify_call::verify,
    endpoint_approval_verify_support::{
        PublicKeys, bind_current_request, resign_identity, sign_fresh, sign_identity, sign_response,
    },
    endpoint_management_values::{identity_exchange, uv_options},
    endpoint_revocation_values::actor,
    endpoint_source_current_tests::source_approve,
};

pub(crate) struct ApprovalFixture {
    pub selected: SignedAuthorityExchangeV1,
    pub begin: SignedAuthorityExchangeV1,
    pub finish: SignedAuthorityExchangeV1,
    pub current: SignedAuthorityExchangeV1,
    pub prepared: EndpointPreparedOperationV2,
    pub browser: ManagementCommandV2,
    pub keys: PublicKeys,
    pub assertion_key: SigningKey,
    pub status_key: SigningKey,
    pub fresh_key: SigningKey,
    pub authority_key: SigningKey,
}

impl ApprovalFixture {
    pub(crate) fn verify(&self) -> Result<(), ContractError> {
        verify(
            &self.selected,
            &self.begin,
            &self.finish,
            &self.current,
            &self.prepared,
            &self.browser,
            &self.keys,
        )
    }

    pub(crate) fn resign_current(&mut self) {
        bind_current_request(&mut self.current);
        resign_identity(&mut self.current, &self.assertion_key, &self.status_key);
        sign_response(&mut self.current, &self.authority_key);
    }

    pub(crate) fn resign_finish(&mut self) {
        sign_fresh(&mut self.finish, &self.fresh_key);
        sign_response(&mut self.finish, &self.authority_key);
    }
}

pub(crate) fn fixture() -> ApprovalFixture {
    let selected_identity = actor("device-a", 'a');
    let envelope = source_approve("device-a", 'a', 140);
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange: mut current,
        prepared,
        finish_uv_exchange: mut finish,
        ..
    } = envelope.evidence
    else {
        unreachable!()
    };
    let browser = envelope.browser_request.command;
    let mut selected = identity_exchange(&selected_identity);
    let mut begin = uv_options(&selected_identity, &prepared);
    align_begin(&mut begin, &finish, &browser);
    let assertion_key = SigningKey::from_bytes(&[1; 32]);
    let status_key = SigningKey::from_bytes(&[2; 32]);
    let fresh_key = SigningKey::from_bytes(&[3; 32]);
    let authority_key = SigningKey::from_bytes(&[4; 32]);
    sign_identity(&mut selected, &assertion_key, &status_key);
    sign_identity(&mut current, &assertion_key, &status_key);
    sign_fresh(&mut finish, &fresh_key);
    for exchange in [&mut selected, &mut begin, &mut finish, &mut current] {
        sign_response(exchange, &authority_key);
    }
    ApprovalFixture {
        selected,
        begin,
        finish,
        current,
        prepared,
        browser,
        keys: PublicKeys {
            assertion: hex::encode(assertion_key.verifying_key().to_bytes()),
            status: hex::encode(status_key.verifying_key().to_bytes()),
            fresh: hex::encode(fresh_key.verifying_key().to_bytes()),
            authority: hex::encode(authority_key.verifying_key().to_bytes()),
        },
        assertion_key,
        status_key,
        fresh_key,
        authority_key,
    }
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
