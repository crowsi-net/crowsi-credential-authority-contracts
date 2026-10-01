use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, AuthorityResult, ResponseOutcome,
    canonical_assertion_payload, canonical_current_status_payload, canonical_fresh_uv,
    canonical_response, command_digest,
};

pub(crate) struct PublicKeys {
    pub assertion: String,
    pub status: String,
    pub fresh: String,
    pub authority: String,
}

pub(crate) fn sign_identity(
    value: &mut SignedAuthorityExchangeV1,
    assertion_key: &SigningKey,
    status_key: &SigningKey,
) {
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.device_posture.state = "compliant".into();
    identity.current_status.device_posture.state = "compliant".into();
    resign_identity(value, assertion_key, status_key);
}

pub(crate) fn resign_identity(
    value: &mut SignedAuthorityExchangeV1,
    assertion_key: &SigningKey,
    status_key: &SigningKey,
) {
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.key_id = "assertion-key".into();
    identity.assertion.signature = hex::encode(
        assertion_key
            .sign(&canonical_assertion_payload(&identity.assertion))
            .to_bytes(),
    );
    identity.current_status.key_id = "status-key".into();
    identity.current_status.signature = hex::encode(
        status_key
            .sign(&canonical_current_status_payload(&identity.current_status))
            .to_bytes(),
    );
}

pub(crate) fn sign_fresh(value: &mut SignedAuthorityExchangeV1, key: &SigningKey) {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvFinished { document },
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    document.key_id = "fresh-key".into();
    document.signature = hex::encode(
        key.sign(&canonical_fresh_uv(document).expect("canonical"))
            .to_bytes(),
    );
}

pub(crate) fn sign_response(value: &mut SignedAuthorityExchangeV1, key: &SigningKey) {
    sign_response_as(value, key, "authority-key");
}

pub(crate) fn sign_response_as(
    value: &mut SignedAuthorityExchangeV1,
    key: &SigningKey,
    key_id: &str,
) {
    value.response.key_id = key_id.into();
    value.response.signature = hex::encode(
        key.sign(&canonical_response(&value.response).expect("canonical"))
            .to_bytes(),
    );
}

pub(crate) fn bind_current_request(value: &mut SignedAuthorityExchangeV1) {
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &value.response.outcome
    else {
        unreachable!()
    };
    let (service, pairwise, device) = (
        identity.assertion.service_id.clone(),
        identity.assertion.pairwise_subject.clone(),
        identity.assertion.device_id.clone(),
    );
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &mut value.request.command
    else {
        unreachable!()
    };
    command.service_id = service;
    command.pairwise_subject = pairwise;
    command.device_id = device;
    let digest = command_digest(&value.request).expect("digest");
    let AuthorityEvidence::Signed(sender) = &mut value.request.evidence[0] else {
        unreachable!()
    };
    sender.binding_sha256.clone_from(&digest);
    value.response.command_digest = digest;
}
