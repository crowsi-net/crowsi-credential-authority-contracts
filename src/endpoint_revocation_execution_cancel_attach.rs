use ihat_identity_assertion_contracts::{AuthorityEvidence, AuthorityRequestV1, command_digest};

use crate::{ContractError, EndpointRevocationExecutionCancellationV1};

/// Adds one exact cancellation token to its evidence-free iHAT cleanup request.
///
/// # Errors
/// Rejects existing evidence, a substituted command, or a token binding mismatch.
pub fn attach_revocation_execution_cancellation(
    value: &AuthorityRequestV1,
    cancellation: &EndpointRevocationExecutionCancellationV1,
) -> Result<AuthorityRequestV1, ContractError> {
    crate::endpoint_revocation_execution_cancel_validation::cancellation(cancellation)?;
    let digest = command_digest(value).map_err(|_| ContractError::Invalid)?;
    if !value.evidence.is_empty()
        || value != &cancellation.cancel_pending_request
        || digest != cancellation.token.binding_sha256
    {
        return Err(ContractError::Invalid);
    }
    let mut result = value.clone();
    result
        .evidence
        .push(AuthorityEvidence::Signed(cancellation.token.clone()));
    Ok(result)
}
