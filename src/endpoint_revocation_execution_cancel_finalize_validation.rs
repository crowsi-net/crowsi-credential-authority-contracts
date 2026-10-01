use ihat_identity_assertion_contracts::{
    AuthorityEvidence, AuthorityResult, ResponseOutcome, VerificationRole,
};

use crate::{
    ContractError, EndpointRevocationExecutionCancelFinalizeRequestV1,
    management_operation_validation::{digest, id},
};

pub(crate) fn validate(
    value: &EndpointRevocationExecutionCancelFinalizeRequestV1,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_execution_cancel_validation::request(&value.cancellation_request)?;
    crate::endpoint_revocation_execution_cancel_validation::cancellation(&value.cancellation)?;
    let [AuthorityEvidence::Signed(token)] =
        value.cancel_pending_exchange.request.evidence.as_slice()
    else {
        return Err(ContractError::Invalid);
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::PendingRevocationCancelled(result),
    } = &value.cancel_pending_exchange.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    let valid = value.schema == crate::ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA
        && id(&value.request_id, 128)
        && digest(&value.operation_id)
        && value.operation_id == value.cancellation_request.operation_id
        && value.cancellation.cancellation_request_sha256
            == crate::endpoint_revocation_execution_cancel_request_digest(
                &value.cancellation_request,
            )?
        && value.cancellation.token.role == VerificationRole::RevocationExecutionCancellation
        && value.cancellation.token.proof_id == value.cancellation.cancellation_id
        && token == &value.cancellation.token
        && result.cancellation_id == value.cancellation.cancellation_id
        && result.finalize_command_id == value.operation_id
        && crate::validate_authority_exchange(
            &value.cancel_pending_exchange,
            "cancel_pending_revocation",
        )
        .is_ok();
    valid.then_some(()).ok_or(ContractError::Invalid)
}
