use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{
    ApprovalRoleDto, AuthorityCommand, AuthorityEvidence, AuthorityResult, ResponseOutcome,
    RevocationCeremonyStateDto, VerificationRole,
};

use crate::endpoint_revocation_support::{independent_envelope, refresh};

fn rejected(value: &EndpointManagementEnvelopeV2) {
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire")),
        Err(ContractError::Invalid)
    );
}

#[test]
fn independent_approval_command_is_exactly_bound_to_c_and_pending_ceremony() {
    for case in 0..8 {
        let mut value = independent_envelope();
        let EndpointManagementEvidenceV2::IndependentApprove {
            revocation_ceremony: ceremony,
            ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let AuthorityCommand::ApproveRevocation(command) = &mut ceremony.approval.request.command
        else {
            unreachable!()
        };
        match case {
            0 => command.command_id = "other-command".into(),
            1 => command.finalize_command_id = "other-final".into(),
            2 => command.attempt_id = "other-attempt".into(),
            3 => command.approval_nonce = "other-nonce".into(),
            4 => command.approval_proof_id = "other-proof".into(),
            5 => command.approval_role = ApprovalRoleDto::RevocationAuthority,
            6 => command.authority_id = "other-authority".into(),
            _ => command.approver_device_id = "device-d".into(),
        }
        refresh(&mut ceremony.approval);
        rejected(&value);
    }
}

#[test]
fn independent_signed_proof_role_key_binding_and_result_are_exact() {
    for case in 0..7 {
        let mut value = independent_envelope();
        let EndpointManagementEvidenceV2::IndependentApprove {
            identity_exchange,
            revocation_ceremony: ceremony,
            ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let identity = identity_evidence_from_exchange(identity_exchange).expect("identity");
        if case < 3 {
            let AuthorityEvidence::Signed(proof) = &mut ceremony.approval.request.evidence[0]
            else {
                unreachable!()
            };
            match case {
                0 => proof.role = VerificationRole::SessionSender,
                1 => proof.binding_sha256 = "88".repeat(32),
                _ => proof.key_id = identity.assertion.key_id.clone(),
            }
        } else {
            let ResponseOutcome::Committed {
                result: AuthorityResult::RevocationApproved(result),
            } = &mut ceremony.approval.response.outcome
            else {
                unreachable!()
            };
            match case {
                3 => result.approval_count = 2,
                4 => result.ready_to_finalize = false,
                5 => result.state = RevocationCeremonyStateDto::AwaitingIndependentApproval,
                _ => result.finalize_command_id = "other-final".into(),
            }
        }
        rejected(&value);
    }
}
