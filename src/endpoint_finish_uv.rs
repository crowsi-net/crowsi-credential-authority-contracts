use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, FreshUvV1, ResponseOutcome, command_digest,
};

use crate::{
    ContractError, ManagementCommandV2, SignedAuthorityExchangeV1, validate_authority_exchange,
};

/// Extracts `FreshUV` only from the exact correlated finish exchange for a browser approval.
///
/// # Errors
/// Rejects a wrong command, outcome, attempt, credential, or `WebAuthn` assertion binding.
pub fn fresh_uv_from_finish_exchange<'a>(
    value: &'a SignedAuthorityExchangeV1,
    browser: &ManagementCommandV2,
) -> Result<&'a FreshUvV1, ContractError> {
    validate_authority_exchange(value, "finish_fresh_user_verification")?;
    let AuthorityCommand::FinishFreshUserVerification(command) = &value.request.command else {
        return Err(ContractError::Invalid);
    };
    if !value.request.evidence.is_empty() {
        return Err(ContractError::Invalid);
    }
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvFinished { document },
    } = &value.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    let (ManagementCommandV2::SourceApprove {
        attempt_id: attempt,
        assertion,
        ..
    }
    | ManagementCommandV2::TargetApprove {
        attempt_id: attempt,
        assertion,
        ..
    }
    | ManagementCommandV2::ApproveRevocation {
        attempt_id: attempt,
        assertion,
        ..
    }) = browser
    else {
        return Err(ContractError::Invalid);
    };
    let exact = command.attempt_id == *attempt
        && command.credential_id == assertion.credential_id
        && command.client_data_json_base64url == assertion.client_data_json_base64url
        && command.authenticator_data_base64url == assertion.authenticator_data_base64url
        && command.signature_der_base64url == assertion.signature_der_base64url
        && document.attempt_id == command.attempt_id
        && document.credential_id == command.credential_id;
    exact.then_some(document).ok_or(ContractError::Invalid)
}

/// Links one finish exchange to the exact previously selected `FreshUV` begin exchange.
///
/// # Errors
/// Rejects a finish for another attempt, credential, challenge, actor, or operation.
pub fn validate_finish_uv_continuity(
    begin: &SignedAuthorityExchangeV1,
    finish: &SignedAuthorityExchangeV1,
    browser: &ManagementCommandV2,
) -> Result<(), ContractError> {
    validate_authority_exchange(begin, "begin_fresh_user_verification")?;
    let fresh = fresh_uv_from_finish_exchange(finish, browser)?;
    let AuthorityCommand::BeginFreshUserVerification(command) = &begin.request.command else {
        return Err(ContractError::Invalid);
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    let AuthorityCommand::FinishFreshUserVerification(finish_command) = &finish.request.command
    else {
        return Err(ContractError::Invalid);
    };
    let begin_request_digest =
        command_digest(&begin.request).map_err(|_| ContractError::Invalid)?;
    let exact = options.attempt_id == finish_command.attempt_id
        && options.attempt_id == fresh.attempt_id
        && command.credential_id == options.credential_id
        && options.credential_id == finish_command.credential_id
        && options.credential_id == fresh.credential_id
        && options.challenge == fresh.challenge
        && options.command_binding_sha256 == begin_request_digest
        && command.operation_digest_sha256 == fresh.operation_digest_sha256
        && command.identity_nonce == fresh.identity_nonce
        && command.source_device_id == fresh.source_device_id
        && command.service_id == fresh.service_id
        && command.pairwise_subject == fresh.pairwise_subject
        && command.session_ref == fresh.session_ref
        && (
            command.subject_epoch,
            command.service_epoch,
            command.device_epoch,
            command.session_epoch,
        ) == (
            fresh.subject_epoch,
            fresh.service_epoch,
            fresh.device_epoch,
            fresh.session_epoch,
        )
        && begin.response.issued_at_epoch_s <= finish.response.issued_at_epoch_s
        && finish.response.issued_at_epoch_s < options.expires_at_epoch_s;
    exact.then_some(()).ok_or(ContractError::Invalid)
}
