use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, AuthorityResult, ResponseOutcome,
};

use crate::{
    endpoint_revocation_support::{refresh, source_envelope},
    endpoint_revocation_values::authentication,
};

#[test]
fn rotated_source_session_cannot_replace_the_reserved_identity_and_begin() {
    let mut value = source_envelope("device-b");
    rotate(&mut value);
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(&value).expect("wire")),
        Err(ContractError::Invalid)
    );

    let mut split = value;
    let EndpointManagementEvidenceV2::SourceApprove {
        revocation_ceremony: Some(ceremony),
        ..
    } = &mut split.evidence
    else {
        unreachable!()
    };
    let AuthorityCommand::BeginDeviceRevocation(command) = &mut ceremony.begin.request.command
    else {
        unreachable!()
    };
    command.source_session_ref = format!("sref_{}", "a".repeat(64));
    refresh(&mut ceremony.begin);
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(&split).expect("wire")),
        Err(ContractError::Invalid)
    );
}

fn rotate(value: &mut EndpointManagementEnvelopeV2) {
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange,
        finish_uv_exchange,
        revocation_ceremony: Some(ceremony),
        ..
    } = &mut value.evidence
    else {
        unreachable!()
    };
    let new_session = format!("sref_{}", "d".repeat(64));
    let new_nonce = "identity-nonce-after-rotation";
    rotate_identity(identity_exchange, &new_session, new_nonce);
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvFinished { document },
    } = &mut finish_uv_exchange.response.outcome
    else {
        unreachable!()
    };
    document.session_ref.clone_from(&new_session);
    document.identity_nonce = new_nonce.into();
    document.issued_at_epoch_s = 140;
    document.expires_at_epoch_s = 160;
    let fresh = document.clone();
    let AuthorityCommand::BeginDeviceRevocation(command) = &mut ceremony.begin.request.command
    else {
        unreachable!()
    };
    command.source_session_ref = new_session;
    command.identity_nonce = new_nonce.into();
    command.authentication = authentication(&fresh);
    ceremony.begin.request.evidence[0] = AuthorityEvidence::FreshUv(fresh);
    refresh(&mut ceremony.begin);
}

fn rotate_identity(value: &mut SignedAuthorityExchangeV1, session: &str, nonce: &str) {
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &mut value.request.command
    else {
        unreachable!()
    };
    command.identity_nonce = nonce.into();
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.session_ref = session.into();
    identity.current_status.session_ref = session.into();
    identity.assertion.nonce = nonce.into();
    identity.current_status.nonce = nonce.into();
    refresh(value);
}
