use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, FreshUvV1, IdentityEvidenceMetadata, ResponseOutcome,
    command_digest,
};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementCommandV2, SignedAuthorityExchangeV1,
    endpoint_operation_digest, validate_authority_exchange,
};

pub(crate) fn options(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    exchange: &SignedAuthorityExchangeV1,
) -> Result<(), ContractError> {
    validate_authority_exchange(exchange, "begin_fresh_user_verification")?;
    let AuthorityCommand::BeginFreshUserVerification(command) = &exchange.request.command else {
        return Err(ContractError::Invalid);
    };
    let digest = endpoint_operation_digest(prepared)?;
    let request_digest = command_digest(&exchange.request).map_err(|_| ContractError::Invalid)?;
    let epochs = &identity.assertion.revocation_epochs;
    let exact = command.identity_nonce == identity.assertion.nonce
        && command.source_device_id == identity.assertion.device_id
        && command.service_id == identity.assertion.service_id
        && command.pairwise_subject == identity.assertion.pairwise_subject
        && command.session_ref == identity.assertion.session_ref
        && command.operation_digest_sha256 == digest
        && (
            command.subject_epoch,
            command.service_epoch,
            command.device_epoch,
            command.session_epoch,
        ) == (
            epochs.subject,
            epochs.service,
            epochs.device,
            epochs.session,
        )
        && matches!(&exchange.response.outcome, ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(value)
        } if value.credential_id == command.credential_id
            && value.command_binding_sha256 == request_digest);
    exact.then_some(()).ok_or(ContractError::Invalid)
}

pub(crate) fn fresh(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    value: &FreshUvV1,
    command: &ManagementCommandV2,
) -> Result<(), ContractError> {
    let (attempt, credential) = match command {
        ManagementCommandV2::SourceApprove {
            attempt_id,
            assertion,
            ..
        }
        | ManagementCommandV2::TargetApprove {
            attempt_id,
            assertion,
            ..
        }
        | ManagementCommandV2::ApproveRevocation {
            attempt_id,
            assertion,
            ..
        } => (attempt_id, &assertion.credential_id),
        _ => return Err(ContractError::Invalid),
    };
    let epochs = &identity.assertion.revocation_epochs;
    let exact = value.user_verified
        && value.attempt_id == *attempt
        && value.credential_id == *credential
        && value.source_device_id == identity.assertion.device_id
        && value.service_id == identity.assertion.service_id
        && value.pairwise_subject == identity.assertion.pairwise_subject
        && value.session_ref == identity.assertion.session_ref
        && value.operation_digest_sha256 == endpoint_operation_digest(prepared)?
        && (
            value.subject_epoch,
            value.service_epoch,
            value.device_epoch,
            value.session_epoch,
        ) == (
            epochs.subject,
            epochs.service,
            epochs.device,
            epochs.session,
        );
    exact.then_some(()).ok_or(ContractError::Invalid)
}
