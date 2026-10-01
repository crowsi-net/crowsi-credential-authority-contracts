use ihat_identity_assertion_contracts::{FreshUvV1, IdentityEvidenceMetadata};

use crate::{
    ContractError, EndpointFreshUvTrustV2, EndpointIdentityTrustV2, EndpointPreparedOperationV2,
    ManagementCommandV2, SignedAuthorityExchangeV1,
};

pub struct EndpointAuthorityResponseTrustV2<'a> {
    pub minimum_config_generation: u64,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
}

pub struct VerifiedEndpointApprovalV2<'a> {
    pub selected_identity: &'a IdentityEvidenceMetadata,
    pub current_identity: &'a IdentityEvidenceMetadata,
    pub fresh_uv: &'a FreshUvV1,
    pub selected_session_sender_key_id: &'a str,
    pub current_session_sender_key_id: &'a str,
    pub selected_session_sender_key_fingerprint: &'a str,
    pub current_session_sender_key_fingerprint: &'a str,
}

/// Verifies the selected UV chain and a submission-current same-session identity.
///
/// # Errors
/// Rejects stale current evidence, selected-chain substitution, role alias, rollback, or drift.
#[allow(clippy::too_many_arguments)]
pub fn verify<'a>(
    selected_identity_exchange: &'a SignedAuthorityExchangeV1,
    selected_begin_exchange: &'a SignedAuthorityExchangeV1,
    finish_exchange: &'a SignedAuthorityExchangeV1,
    current_identity_exchange: &'a SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    browser: &ManagementCommandV2,
    authority: &EndpointAuthorityResponseTrustV2<'_>,
    identity_trust: &EndpointIdentityTrustV2<'_>,
    fresh_trust: &EndpointFreshUvTrustV2<'_>,
) -> Result<VerifiedEndpointApprovalV2<'a>, ContractError> {
    let selected = crate::identity_evidence_from_exchange(selected_identity_exchange)?;
    let current = crate::identity_evidence_from_exchange(current_identity_exchange)?;
    let fresh = crate::fresh_uv_from_finish_exchange(finish_exchange, browser)?;
    let selected_sender = crate::endpoint_approval_context::sender(selected_identity_exchange)?;
    let current_sender = crate::endpoint_approval_context::sender(current_identity_exchange)?;
    let now = identity_trust.now_epoch_s;
    let trust_distinct = crate::endpoint_approval_context::trusts(
        authority,
        identity_trust,
        fresh_trust,
        &current_sender,
    );
    if now != fresh_trust.now_epoch_s || !trust_distinct {
        return Err(ContractError::Invalid);
    }
    historic(
        selected_identity_exchange,
        "issue_current_device_identity_evidence",
        authority,
    )?;
    historic(
        selected_begin_exchange,
        "begin_fresh_user_verification",
        authority,
    )?;
    current_exchange(
        finish_exchange,
        "finish_fresh_user_verification",
        authority,
        now,
    )?;
    current_exchange(
        current_identity_exchange,
        "issue_current_device_identity_evidence",
        authority,
        now,
    )?;
    let selected_time = selected_begin_exchange.response.issued_at_epoch_s;
    crate::verify_endpoint_identity_at(selected, &identity_at(identity_trust, selected_time))?;
    crate::verify_endpoint_identity_at(current, identity_trust)?;
    crate::endpoint_identity_operation::options(selected, prepared, selected_begin_exchange)?;
    crate::validate_finish_uv_continuity(selected_begin_exchange, finish_exchange, browser)?;
    crate::verify_endpoint_fresh_uv_at(current, prepared, fresh, browser, fresh_trust)?;
    if !crate::endpoint_approval_order::ordered(
        selected_identity_exchange,
        selected_begin_exchange,
        finish_exchange,
        current_identity_exchange,
        current,
        fresh,
    ) || !crate::endpoint_approval_context::stable(
        selected,
        current,
        fresh,
        &selected_sender,
        &current_sender,
    ) {
        return Err(ContractError::Invalid);
    }
    Ok(VerifiedEndpointApprovalV2 {
        selected_identity: selected,
        current_identity: current,
        fresh_uv: fresh,
        selected_session_sender_key_id: selected_sender.key_id,
        current_session_sender_key_id: current_sender.key_id,
        selected_session_sender_key_fingerprint: selected_sender.fingerprint,
        current_session_sender_key_fingerprint: current_sender.fingerprint,
    })
}

fn historic(
    value: &SignedAuthorityExchangeV1,
    kind: &str,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
) -> Result<(), ContractError> {
    current_exchange(value, kind, trust, value.response.issued_at_epoch_s)
}

fn current_exchange(
    value: &SignedAuthorityExchangeV1,
    kind: &str,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    now: u64,
) -> Result<(), ContractError> {
    crate::verify_authority_exchange_at(
        value,
        kind,
        trust.minimum_config_generation,
        trust.key_id,
        trust.public_key_hex,
        now,
    )
}

fn identity_at<'a>(
    value: &'a EndpointIdentityTrustV2<'a>,
    now: u64,
) -> EndpointIdentityTrustV2<'a> {
    EndpointIdentityTrustV2 {
        issuer: value.issuer,
        audience: value.audience,
        assertion_key_id: value.assertion_key_id,
        assertion_public_key_hex: value.assertion_public_key_hex,
        current_status_key_id: value.current_status_key_id,
        current_status_public_key_hex: value.current_status_public_key_hex,
        now_epoch_s: now,
    }
}
