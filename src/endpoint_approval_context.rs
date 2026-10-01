use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, FreshUvV1, IdentityEvidenceMetadata,
};

use crate::{
    ContractError, EndpointAuthorityResponseTrustV2, EndpointFreshUvTrustV2,
    EndpointIdentityTrustV2, SignedAuthorityExchangeV1,
};

pub(crate) struct SenderContext<'a> {
    pub key_id: &'a str,
    pub fingerprint: &'a str,
}

pub(crate) fn sender(
    value: &SignedAuthorityExchangeV1,
) -> Result<SenderContext<'_>, ContractError> {
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &value.request.command
    else {
        return Err(ContractError::Invalid);
    };
    let [AuthorityEvidence::Signed(sender)] = value.request.evidence.as_slice() else {
        return Err(ContractError::Invalid);
    };
    Ok(SenderContext {
        key_id: &sender.key_id,
        fingerprint: &command.session_sender_key_fingerprint,
    })
}

pub(crate) fn stable(
    selected: &IdentityEvidenceMetadata,
    current: &IdentityEvidenceMetadata,
    fresh: &FreshUvV1,
    selected_sender: &SenderContext<'_>,
    current_sender: &SenderContext<'_>,
) -> bool {
    let old = &selected.assertion;
    let new = &current.assertion;
    old.issuer == new.issuer
        && old.audience == new.audience
        && old.service_id == new.service_id
        && old.pairwise_subject == new.pairwise_subject
        && old.device_id == new.device_id
        && old.device_proof_key_ref == new.device_proof_key_ref
        && old.session_ref == new.session_ref
        && old.device_posture == new.device_posture
        && old.revocation_epochs == new.revocation_epochs
        && old.issued_at_epoch_s == selected.current_status.issued_at_epoch_s
        && new.issued_at_epoch_s == current.current_status.issued_at_epoch_s
        && fresh.identity_nonce == old.nonce
        && selected_sender.key_id == current_sender.key_id
        && selected_sender.fingerprint == current_sender.fingerprint
        && sender_roles_distinct(current, fresh, current_sender)
}

pub(crate) fn trust_roles_distinct(ids: [&str; 5], public_keys: [&str; 4]) -> bool {
    pairwise_distinct(&ids) && pairwise_distinct(&public_keys)
}

pub(crate) fn trusts(
    authority: &EndpointAuthorityResponseTrustV2<'_>,
    identity: &EndpointIdentityTrustV2<'_>,
    fresh: &EndpointFreshUvTrustV2<'_>,
    sender: &SenderContext<'_>,
) -> bool {
    authority.minimum_config_generation > 0
        && trust_roles_distinct(
            [
                authority.key_id,
                identity.assertion_key_id,
                identity.current_status_key_id,
                fresh.key_id,
                sender.key_id,
            ],
            [
                authority.public_key_hex,
                identity.assertion_public_key_hex,
                identity.current_status_public_key_hex,
                fresh.public_key_hex,
            ],
        )
}

fn pairwise_distinct(values: &[&str]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| values[..index].iter().all(|prior| prior != value))
}

fn sender_roles_distinct(
    current: &IdentityEvidenceMetadata,
    fresh: &FreshUvV1,
    sender: &SenderContext<'_>,
) -> bool {
    let key_id = sender.key_id;
    key_id != current.assertion.device_proof_key_ref
        && key_id != current.assertion.key_id
        && key_id != current.current_status.key_id
        && key_id != fresh.key_id
}
