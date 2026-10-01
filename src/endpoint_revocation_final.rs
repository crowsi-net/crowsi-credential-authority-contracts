use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, RevocationCeremonyMetadata,
};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementIntentV2, SignedAuthorityExchangeV1,
    validate_authority_exchange,
};

pub(crate) fn validate(
    prepared: &EndpointPreparedOperationV2,
    begun: &RevocationCeremonyMetadata,
    value: &SignedAuthorityExchangeV1,
) -> Result<(), ContractError> {
    if value.response.issued_at_epoch_s >= begun.expires_at_epoch_s {
        return Err(ContractError::Invalid);
    }
    let target_digest = shape(prepared, value)?;
    (target_digest == begun.target_digest)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

pub(crate) fn shape<'a>(
    prepared: &EndpointPreparedOperationV2,
    value: &'a SignedAuthorityExchangeV1,
) -> Result<&'a str, ContractError> {
    let allowed_evidence = value.request.evidence.is_empty()
        || matches!(value.request.evidence.as_slice(), [
            ihat_identity_assertion_contracts::AuthorityEvidence::Signed(item)
        ] if item.role == ihat_identity_assertion_contracts::VerificationRole::RevocationExecutionReservation);
    if !allowed_evidence {
        return Err(ContractError::Invalid);
    }
    let mut command_only = value.request.clone();
    command_only.evidence.clear();
    request(prepared, &command_only)?;
    let requirements = crate::endpoint_revocation_binding::requirements(prepared)?;
    match (
        &prepared.intent,
        &value.request.command,
        &value.response.outcome,
    ) {
        (
            ManagementIntentV2::DeviceRevocation {
                service_id,
                target_device_ref,
                expected_device_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeDeviceByRef(command),
            ResponseOutcome::Committed {
                result: AuthorityResult::DeviceRevocation(result),
            },
        ) if command.command_id == prepared.operation_id
            && command.service_id == *service_id
            && command.pairwise_subject == prepared.pairwise_subject
            && command.target_device_id == *target_device_ref
            && command.expected_device_epoch == *expected_device_revocation_epoch
            && command.authority_id == requirements.finalization_authority_id
            && result.previous_device_epoch == *expected_device_revocation_epoch
            && result.current_device_epoch > result.previous_device_epoch
            && Some(result.revoked_session_count)
                == requirements.expected_revoked_session_count =>
        {
            validate_authority_exchange(value, "revoke_device_by_ref")?;
            Ok(&result.target_digest)
        }
        (
            ManagementIntentV2::SessionRevocation {
                service_id,
                target_session_ref,
                expected_session_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeSessionByRef(command),
            ResponseOutcome::Committed {
                result: AuthorityResult::Revocation(result),
            },
        ) if command.command_id == prepared.operation_id
            && command.service_id == *service_id
            && command.pairwise_subject == prepared.pairwise_subject
            && command.session_ref == *target_session_ref
            && command.expected_epoch == *expected_session_revocation_epoch
            && command.authority_id == requirements.finalization_authority_id
            && result.previous_epoch == *expected_session_revocation_epoch
            && result.current_epoch > result.previous_epoch =>
        {
            validate_authority_exchange(value, "revoke_session_by_ref")?;
            Ok(&result.target_digest)
        }
        _ => Err(ContractError::Invalid),
    }
}

pub(crate) fn request(
    prepared: &EndpointPreparedOperationV2,
    value: &ihat_identity_assertion_contracts::AuthorityRequestV1,
) -> Result<(), ContractError> {
    let requirements = crate::endpoint_revocation_binding::requirements(prepared)?;
    let wire = serde_json::to_vec(value).map_err(|_| ContractError::Invalid)?;
    if !value.evidence.is_empty() {
        return Err(ContractError::Invalid);
    }
    ihat_identity_assertion_contracts::decode_authority_request_strict(&wire)
        .map_err(|_| ContractError::Invalid)?;
    let exact = match (&prepared.intent, &value.command) {
        (
            ManagementIntentV2::DeviceRevocation {
                service_id,
                target_device_ref,
                expected_device_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeDeviceByRef(command),
        ) => {
            command.command_id == prepared.operation_id
                && command.service_id == *service_id
                && command.pairwise_subject == prepared.pairwise_subject
                && command.target_device_id == *target_device_ref
                && command.expected_device_epoch == *expected_device_revocation_epoch
                && command.authority_id == requirements.finalization_authority_id
        }
        (
            ManagementIntentV2::SessionRevocation {
                service_id,
                target_session_ref,
                expected_session_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeSessionByRef(command),
        ) => {
            command.command_id == prepared.operation_id
                && command.service_id == *service_id
                && command.pairwise_subject == prepared.pairwise_subject
                && command.session_ref == *target_session_ref
                && command.expected_epoch == *expected_session_revocation_epoch
                && command.authority_id == requirements.finalization_authority_id
        }
        _ => false,
    };
    exact.then_some(()).ok_or(ContractError::Invalid)
}
