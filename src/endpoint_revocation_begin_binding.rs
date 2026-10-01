use ihat_identity_assertion_contracts::{
    AuthorityEvidence, FreshAuthenticationDto, FreshUvV1, VerificationRole, command_digest,
};

use crate::{EndpointPreparedOperationV2, SignedAuthorityExchangeV1, revocation_begin_command_id};

#[allow(clippy::too_many_arguments)]
pub(crate) fn common(
    command_id: &str,
    finalize_id: &str,
    device: &str,
    session: &str,
    pairwise: &str,
    nonce: &str,
    sender_proof_id: &str,
    authentication: &FreshAuthenticationDto,
    prepared: &EndpointPreparedOperationV2,
    exchange: &SignedAuthorityExchangeV1,
    expected_fresh: Option<&FreshUvV1>,
) -> bool {
    let Ok(expected_command_id) = revocation_begin_command_id(prepared) else {
        return false;
    };
    let Ok(binding) = command_digest(&exchange.request) else {
        return false;
    };
    let [
        AuthorityEvidence::FreshUv(fresh),
        AuthorityEvidence::Signed(sender),
    ] = exchange.request.evidence.as_slice()
    else {
        return false;
    };
    command_id == expected_command_id
        && finalize_id == prepared.operation_id
        && device == prepared.source_device_ref
        && device == fresh.source_device_id
        && session == fresh.session_ref
        && pairwise == prepared.pairwise_subject
        && pairwise == fresh.pairwise_subject
        && nonce == fresh.identity_nonce
        && sender_proof_id == sender.proof_id
        && sender.role == VerificationRole::SessionSender
        && sender.binding_sha256 == binding
        && sender.key_id != fresh.key_id
        && expected_fresh.is_none_or(|expected| expected == fresh)
        && authentication_matches(authentication, fresh)
}

fn authentication_matches(value: &FreshAuthenticationDto, fresh: &FreshUvV1) -> bool {
    value.proof_id == fresh.proof_id
        && value.authenticator_id == fresh.credential_id
        && value.authenticator_key_fingerprint == fresh.authenticator_key_fingerprint
        && value.kind == fresh.kind
        && value.user_verified == fresh.user_verified
        && value.issued_at_epoch_s == fresh.issued_at_epoch_s
        && value.expires_at_epoch_s == fresh.expires_at_epoch_s
        && value.service_id == fresh.service_id
        && value.pairwise_subject == fresh.pairwise_subject
        && value.session_ref == fresh.session_ref
        && value.operation_digest_sha256 == fresh.operation_digest_sha256
        && (
            value.subject_epoch,
            value.service_epoch,
            value.device_epoch,
            value.session_epoch,
        ) == (
            fresh.subject_epoch,
            fresh.service_epoch,
            fresh.device_epoch,
            fresh.session_epoch,
        )
}
