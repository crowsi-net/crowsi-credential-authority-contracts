use ihat_identity_assertion_contracts::{AuthorityEvidence, AuthorityRequestV1, command_digest};

use crate::{ContractError, EndpointRevocationExecutionCancellationCleanupV1};

/// Attaches the exact root cleanup proof to its evidence-free acknowledgement command.
///
/// # Errors
/// Rejects existing evidence or a command/token binding mismatch.
pub fn attach_revocation_cancellation_cleanup(
    value: &AuthorityRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<AuthorityRequestV1, ContractError> {
    crate::endpoint_revocation_execution_cancel_cleanup_validation::validate(cleanup)?;
    if value != &cleanup.acknowledge_request
        || !value.evidence.is_empty()
        || command_digest(value).map_err(|_| ContractError::Invalid)?
            != cleanup.token.binding_sha256
    {
        return Err(ContractError::Invalid);
    }
    let mut result = value.clone();
    result
        .evidence
        .push(AuthorityEvidence::Signed(cleanup.token.clone()));
    Ok(result)
}
