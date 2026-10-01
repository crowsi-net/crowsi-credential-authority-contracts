use ihat_identity_assertion_contracts::{
    ApprovalRoleDto, AuthorityCommand, AuthorityEvidence, AuthorityResult,
    IdentityEvidenceMetadata, ResponseOutcome, RevocationCeremonyMetadata,
    RevocationCeremonyStateDto, VerificationRole, command_digest,
};

use crate::{
    ContractError, EndpointPreparedOperationV2, RevocationRequirementsV2,
    SignedAuthorityExchangeV1, revocation_approval_command_id, validate_authority_exchange,
};

pub(crate) fn validate(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    requirements: &RevocationRequirementsV2,
    begun: &RevocationCeremonyMetadata,
    value: &SignedAuthorityExchangeV1,
) -> Result<(), ContractError> {
    validate_authority_exchange(value, "approve_revocation")?;
    let AuthorityCommand::ApproveRevocation(command) = &value.request.command else {
        return Err(ContractError::Invalid);
    };
    let [AuthorityEvidence::Signed(proof)] = value.request.evidence.as_slice() else {
        return Err(ContractError::Invalid);
    };
    let binding = command_digest(&value.request).map_err(|_| ContractError::Invalid)?;
    let required = requirements
        .required_approval_authority_ref
        .as_deref()
        .ok_or(ContractError::Invalid)?;
    let expected_role = match command.approval_role {
        ApprovalRoleDto::RevocationAuthority => VerificationRole::RevocationAuthority,
        ApprovalRoleDto::RecoveryApproval => VerificationRole::RecoveryApproval,
    };
    let actor = &identity.assertion.device_id;
    let command_id = revocation_approval_command_id(prepared, actor)?;
    let response_exact = matches!(&value.response.outcome, ResponseOutcome::Committed {
        result: AuthorityResult::RevocationApproved(result)
    } if result.attempt_id == begun.attempt_id
        && result.finalize_command_id == prepared.operation_id
        && result.ready_to_finalize
        && result.approval_count == 1
        && result.state == RevocationCeremonyStateDto::ReadyToFinalize);
    let exact = command.command_id == command_id
        && command.finalize_command_id == prepared.operation_id
        && command.attempt_id == begun.attempt_id
        && command.approval_nonce
            == *begun
                .approval_nonce
                .as_ref()
                .ok_or(ContractError::Invalid)?
        && command.approval_proof_id == proof.proof_id
        && command.authority_id == required
        && command.approver_device_id == *actor
        && proof.role == expected_role
        && proof.binding_sha256 == binding
        && proof.key_id != identity.assertion.key_id
        && proof.key_id != identity.current_status.key_id
        && value.response.issued_at_epoch_s < begun.expires_at_epoch_s
        && response_exact;
    exact.then_some(()).ok_or(ContractError::Invalid)
}
