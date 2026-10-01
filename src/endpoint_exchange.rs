use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityEvidence,
    AuthorityResponseBinding, AuthorityResult, IdentityEvidenceMetadata, ResponseOutcome,
    VerificationRole, command_digest, current_status_matches_assertion,
    decode_authority_request_strict, decode_authority_response_strict,
    verify_authority_response_at,
};

use crate::{ContractError, SignedAuthorityExchangeV1};

/// Checks the closed request/response correlation before a consumer verifies the response key.
///
/// # Errors
/// Rejects missing, cross-request, reordered, wrong-command, or rollback-shaped exchanges.
pub fn validate_authority_exchange(
    value: &SignedAuthorityExchangeV1,
    expected_command_type: &str,
) -> Result<(), ContractError> {
    let request_wire = serde_json::to_vec(&value.request);
    let response_wire = serde_json::to_vec(&value.response);
    let strict = request_wire.is_ok_and(|wire| decode_authority_request_strict(&wire).is_ok())
        && response_wire.is_ok_and(|wire| decode_authority_response_strict(&wire).is_ok());
    let valid = strict
        && value.request.schema == AUTHORITY_REQUEST_SCHEMA
        && value.response.schema == AUTHORITY_RESPONSE_SCHEMA
        && value.request.command.type_name() == expected_command_type
        && value.response.command_type == expected_command_type
        && value.response.request_id == value.request.request_id
        && value.response.config_generation > 0
        && command_digest(&value.request)
            .is_ok_and(|digest| digest == value.response.command_digest);
    if valid {
        Ok(())
    } else {
        Err(ContractError::Invalid)
    }
}

/// Extracts current identity only from a correlated, committed iHAT authority exchange.
///
/// # Errors
/// Rejects bare/substituted identity, wrong commands, rejected/unknown outcomes, or context drift.
pub fn identity_evidence_from_exchange(
    value: &SignedAuthorityExchangeV1,
) -> Result<&IdentityEvidenceMetadata, ContractError> {
    validate_authority_exchange(value, "issue_current_device_identity_evidence")?;
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &value.request.command
    else {
        return Err(ContractError::Invalid);
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &value.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    let [AuthorityEvidence::Signed(sender)] = value.request.evidence.as_slice() else {
        return Err(ContractError::Invalid);
    };
    let request_digest = command_digest(&value.request).map_err(|_| ContractError::Invalid)?;
    let assertion = &identity.assertion;
    if sender.role == VerificationRole::SessionSender
        && sender.proof_id == command.session_sender_proof_id
        && sender.binding_sha256 == request_digest
        && command.service_id == assertion.service_id
        && command.pairwise_subject == assertion.pairwise_subject
        && command.device_id == assertion.device_id
        && command.audience == assertion.audience
        && command.identity_nonce == assertion.nonce
        && current_status_matches_assertion(&identity.current_status, assertion)
    {
        Ok(identity)
    } else {
        Err(ContractError::Invalid)
    }
}

/// Verifies a correlated exchange response with a pinned authority key, generation, and clock.
///
/// # Errors
/// Rejects malformed, cross-request, stale, rollback, wrong-key, or invalid-signature responses.
pub fn verify_authority_exchange_at(
    value: &SignedAuthorityExchangeV1,
    expected_command_type: &str,
    minimum_config_generation: u64,
    expected_key_id: &str,
    public_key_hex: &str,
    now_epoch_s: u64,
) -> Result<(), ContractError> {
    validate_authority_exchange(value, expected_command_type)?;
    let digest = command_digest(&value.request).map_err(|_| ContractError::Invalid)?;
    verify_authority_response_at(
        &value.response,
        &AuthorityResponseBinding {
            request_id: &value.request.request_id,
            command_type: expected_command_type,
            command_digest: &digest,
            minimum_config_generation,
        },
        expected_key_id,
        public_key_hex,
        now_epoch_s,
    )
    .map_err(|_| ContractError::Invalid)
}

/// Verifies only the signed, correlated authority response under previously accepted trust.
///
/// This deliberately does not apply the response wrapper's current-time window. It is safe only
/// after a caller has durably accepted the exact operation and pinned this response key before an
/// irreversible side effect, then receives the exact signed result during crash recovery.
///
/// # Errors
/// Rejects malformed correlation, command substitution, generation rollback, key drift, or an
/// invalid response signature.
pub fn verify_authority_exchange_historic(
    value: &SignedAuthorityExchangeV1,
    expected_command_type: &str,
    minimum_config_generation: u64,
    expected_key_id: &str,
    public_key_hex: &str,
) -> Result<(), ContractError> {
    validate_authority_exchange(value, expected_command_type)?;
    if value.response.config_generation < minimum_config_generation
        || value.response.key_id != expected_key_id
    {
        return Err(ContractError::Invalid);
    }
    let canonical = ihat_identity_assertion_contracts::canonical_response(&value.response)
        .map_err(|_| ContractError::Invalid)?;
    crate::management_crypto::verify(public_key_hex, &value.response.signature, &canonical)
}
