use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, command_digest,
};

use crate::{
    ContractError, EndpointRevocationExecutionCancelFinalizeRequestV1,
    EndpointRevocationExecutionCancellationV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationExecutionCancelResponseTrustV1<'a> {
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_config_generation: u64,
    pub now_epoch_s: u64,
}

/// Correlates one cleanup acknowledgement with its exact accepted cancellation token.
///
/// # Errors
/// Rejects request, token, command, attempt, target, result, or response-key substitution.
pub fn validate_endpoint_revocation_execution_cancel_finalize_against_acceptance(
    value: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cancellation: &EndpointRevocationExecutionCancellationV1,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_finalize_validation::validate(value)?;
    crate::endpoint_revocation_execution_cancel_validation::cancellation(cancellation)?;
    let expected = crate::attach_revocation_execution_cancellation(
        &cancellation.cancel_pending_request,
        cancellation,
    )?;
    let AuthorityCommand::CancelPendingRevocation(command) =
        &cancellation.cancel_pending_request.command
    else {
        return Err(ContractError::Invalid);
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::PendingRevocationCancelled(result),
    } = &value.cancel_pending_exchange.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    let exact =
        crate::endpoint_revocation_execution_cancel_request_digest(&value.cancellation_request)?
            == cancellation.cancellation_request_sha256
            && value.cancellation.cancellation_id == cancellation.cancellation_id
            && value.cancellation.token == cancellation.token
            && value.cancellation.cancellation_request_sha256
                == cancellation.cancellation_request_sha256
            && value.cancel_pending_exchange.request == expected
            && command_digest(&value.cancel_pending_exchange.request)
                .map_err(|_| ContractError::Invalid)?
                == cancellation.token.binding_sha256
            && result.attempt_id == command.attempt_id
            && result.finalize_command_id == command.finalize_command_id
            && result.target_digest_sha256 == command.target_digest_sha256
            && result.cancellation_id == cancellation.cancellation_id
            && value.cancel_pending_exchange.response.key_id
                == value.cancellation_request.begin_exchange.response.key_id
            && value.cancel_pending_exchange.response.config_generation
                >= value
                    .cancellation_request
                    .begin_exchange
                    .response
                    .config_generation;
    exact.then_some(()).ok_or(ContractError::Invalid)
}

/// Verifies an exact cleanup response after its Begin and response wrapper have expired.
///
/// # Errors
/// Rejects acceptance drift, future output, response-key drift, rollback, or invalid signature.
pub fn verify_endpoint_revocation_execution_cancel_response_historic_at(
    value: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cancellation: &EndpointRevocationExecutionCancellationV1,
    trust: &EndpointRevocationExecutionCancelResponseTrustV1<'_>,
) -> Result<(), ContractError> {
    validate_endpoint_revocation_execution_cancel_finalize_against_acceptance(value, cancellation)?;
    let response = &value.cancel_pending_exchange.response;
    if response.key_id != trust.key_id
        || value.cancellation_request.begin_exchange.response.key_id != trust.key_id
        || response.config_generation < trust.minimum_config_generation
        || response.issued_at_epoch_s < cancellation.issued_at_epoch_s
        || response.issued_at_epoch_s < cancellation.token.issued_at_epoch_s
        || response.issued_at_epoch_s > trust.now_epoch_s
    {
        return Err(ContractError::Invalid);
    }
    crate::verify_authority_exchange_historic(
        &value.cancel_pending_exchange,
        "cancel_pending_revocation",
        trust.minimum_config_generation,
        trust.key_id,
        trust.public_key_hex,
    )
}
