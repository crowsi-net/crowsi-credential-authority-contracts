use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, FreshUvV1, ResponseOutcome, RevocationCeremonyMetadata,
    RevocationCeremonyStateDto,
};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementIntentV2, SignedAuthorityExchangeV1,
    validate_authority_exchange,
};

pub(crate) fn validate<'a>(
    prepared: &EndpointPreparedOperationV2,
    value: &'a SignedAuthorityExchangeV1,
    expected_fresh: Option<&FreshUvV1>,
) -> Result<&'a RevocationCeremonyMetadata, ContractError> {
    let expected = match prepared.intent {
        ManagementIntentV2::DeviceRevocation { .. } => "begin_device_revocation",
        ManagementIntentV2::SessionRevocation { .. } => "begin_session_revocation",
        ManagementIntentV2::DeviceTransfer { .. } => return Err(ContractError::Invalid),
    };
    validate_authority_exchange(value, expected)?;
    let command_exact = match &value.request.command {
        AuthorityCommand::BeginDeviceRevocation(command) => {
            matches!(&prepared.intent, ManagementIntentV2::DeviceRevocation {
                service_id, target_device_ref, expected_device_revocation_epoch, ..
            } if command.service_id == *service_id
                && command.target_device_id == *target_device_ref
                && command.expected_device_epoch == *expected_device_revocation_epoch)
                && crate::endpoint_revocation_begin_binding::common(
                    &command.command_id,
                    &command.finalize_command_id,
                    &command.source_device_id,
                    &command.source_session_ref,
                    &command.pairwise_subject,
                    &command.identity_nonce,
                    &command.sender_proof_id,
                    &command.authentication,
                    prepared,
                    value,
                    expected_fresh,
                )
        }
        AuthorityCommand::BeginSessionRevocation(command) => {
            matches!(&prepared.intent, ManagementIntentV2::SessionRevocation {
                service_id, target_session_ref, expected_session_revocation_epoch, ..
            } if command.service_id == *service_id
                && command.target_session_ref == *target_session_ref
                && command.expected_session_epoch == *expected_session_revocation_epoch)
                && crate::endpoint_revocation_begin_binding::common(
                    &command.command_id,
                    &command.finalize_command_id,
                    &command.source_device_id,
                    &command.source_session_ref,
                    &command.pairwise_subject,
                    &command.identity_nonce,
                    &command.sender_proof_id,
                    &command.authentication,
                    prepared,
                    value,
                    expected_fresh,
                )
        }
        _ => false,
    };
    if !command_exact {
        return Err(ContractError::Invalid);
    }
    response(prepared, value)
}

fn response<'a>(
    prepared: &EndpointPreparedOperationV2,
    exchange: &'a SignedAuthorityExchangeV1,
) -> Result<&'a RevocationCeremonyMetadata, ContractError> {
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(result),
    } = &exchange.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    let requirements = crate::endpoint_revocation_requirements::validate(prepared)?;
    let independent = requirements.target_device_ref != prepared.source_device_ref;
    let expected_state = if independent {
        RevocationCeremonyStateDto::AwaitingIndependentApproval
    } else {
        RevocationCeremonyStateDto::ReadyToFinalize
    };
    let approval_shape = if independent {
        result
            .approval_nonce
            .as_ref()
            .is_some_and(|value| bounded(value))
            && requirements
                .required_approval_authority_ref
                .as_ref()
                .is_some_and(|value| bounded(value))
    } else {
        result.approval_nonce.is_none() && requirements.required_approval_authority_ref.is_none()
    };
    let lifetime = result
        .expires_at_epoch_s
        .checked_sub(exchange.response.issued_at_epoch_s);
    let exact = result.finalize_command_id == prepared.operation_id
        && result.independent_approval_required == independent
        && result.state == expected_state
        && bounded(&result.attempt_id)
        && lower_hex_32(&result.target_digest)
        && lifetime.is_some_and(|seconds| (1..=300).contains(&seconds))
        && approval_shape;
    exact.then_some(result).ok_or(ContractError::Invalid)
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}
fn lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
