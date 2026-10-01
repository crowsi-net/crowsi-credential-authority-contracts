use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    ContractError, EndpointRevocationExecutionCancellationCleanupV1, SignedAuthorityExchangeV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationCancellationCleanupResponseTrustV1<'a> {
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub now_epoch_s: u64,
}

/// Correlates one iHAT cleanup acknowledgement with its exact root-authorized command.
///
/// # Errors
/// Rejects command, token, cancellation, cleanup, result, or response-key substitution.
pub fn validate_endpoint_revocation_cancellation_cleanup_exchange(
    value: &SignedAuthorityExchangeV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_cleanup_validation::validate(cleanup)?;
    let expected =
        crate::attach_revocation_cancellation_cleanup(&cleanup.acknowledge_request, cleanup)?;
    let ResponseOutcome::Committed {
        result: AuthorityResult::PendingCancellationAcknowledged(result),
    } = &value.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    let valid = value.request == expected
        && result.cancellation_id == cleanup.cancellation_id
        && result.cleanup_id == cleanup.cleanup_id
        && crate::validate_authority_exchange(value, "acknowledge_pending_cancellation").is_ok();
    valid.then_some(()).ok_or(ContractError::Invalid)
}

/// Verifies an iHAT cleanup acknowledgement after wrapper expiry.
///
/// The root-authorized request and committed result are exact. The response may be freshly
/// re-signed by the current iHAT response key after the pending state and old cache are removed.
///
/// # Errors
/// Rejects future output, response trust drift, rollback, or an invalid signature.
pub fn verify_endpoint_revocation_cancellation_cleanup_exchange_historic_at(
    value: &SignedAuthorityExchangeV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    trust: &EndpointRevocationCancellationCleanupResponseTrustV1<'_>,
) -> Result<(), ContractError> {
    validate_endpoint_revocation_cancellation_cleanup_exchange(value, cleanup)?;
    let response = &value.response;
    if response.key_id != trust.key_id
        || response.config_generation < trust.minimum_config_generation
        || response.issued_at_epoch_s < cleanup.issued_at_epoch_s
        || response.issued_at_epoch_s < cleanup.token.issued_at_epoch_s
        || response.issued_at_epoch_s > trust.now_epoch_s
    {
        return Err(ContractError::Invalid);
    }
    crate::verify_authority_exchange_historic(
        value,
        "acknowledge_pending_cancellation",
        trust.minimum_config_generation,
        trust.key_id,
        trust.public_key_hex,
    )
}
