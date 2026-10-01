use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, AuthorityResult, ResponseOutcome,
    RevocationCeremonyStateDto, VerificationRole,
};

use crate::endpoint_revocation_support::{refresh, source_envelope};

fn rejected(value: &EndpointManagementEnvelopeV2) {
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire")),
        Err(ContractError::Invalid)
    );
}

#[test]
fn begin_command_and_sender_evidence_are_bound_field_by_field() {
    for case in 0..10 {
        let mut value = source_envelope("device-b");
        let EndpointManagementEvidenceV2::SourceApprove {
            revocation_ceremony: Some(ceremony),
            ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let AuthorityCommand::BeginDeviceRevocation(command) = &mut ceremony.begin.request.command
        else {
            unreachable!()
        };
        match case {
            0 => command.command_id = "other-begin".into(),
            1 => command.finalize_command_id = "other-final".into(),
            2 => command.sender_proof_id = "other-proof".into(),
            3 => command.source_device_id = "device-c".into(),
            4 => command.source_session_ref = format!("sref_{}", "c".repeat(64)),
            5 => command.pairwise_subject = "other-pairwise".into(),
            6 => command.identity_nonce = "other-nonce".into(),
            7 => command.authentication.session_epoch += 1,
            8 => {
                if let AuthorityEvidence::Signed(proof) = &mut ceremony.begin.request.evidence[1] {
                    proof.role = VerificationRole::RecoveryApproval;
                }
            }
            _ => {
                if let AuthorityEvidence::Signed(proof) = &mut ceremony.begin.request.evidence[1] {
                    proof.key_id = "uv-key-credential-a".into();
                }
            }
        }
        refresh(&mut ceremony.begin);
        rejected(&value);
    }
}

#[test]
fn begin_response_exact_target_state_expiry_and_nonce_are_bound() {
    for case in 0..5 {
        let mut value = source_envelope("device-b");
        let EndpointManagementEvidenceV2::SourceApprove {
            revocation_ceremony: Some(ceremony),
            ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let ResponseOutcome::Committed {
            result: AuthorityResult::RevocationBegun(result),
        } = &mut ceremony.begin.response.outcome
        else {
            unreachable!()
        };
        match case {
            0 => result.attempt_id.clear(),
            1 => result.expires_at_epoch_s = ceremony.begin.response.issued_at_epoch_s,
            2 => result.independent_approval_required = false,
            3 => result.state = RevocationCeremonyStateDto::ReadyToFinalize,
            _ => result.approval_nonce = None,
        }
        rejected(&value);
    }
}

#[test]
fn source_fresh_uv_must_be_the_exact_evidence_document() {
    let mut value = source_envelope("device-b");
    let EndpointManagementEvidenceV2::SourceApprove {
        revocation_ceremony: Some(ceremony),
        ..
    } = &mut value.evidence
    else {
        unreachable!()
    };
    let AuthorityEvidence::FreshUv(fresh) = &mut ceremony.begin.request.evidence[0] else {
        unreachable!()
    };
    fresh.proof_id = "substituted-source-uv".into();
    refresh(&mut ceremony.begin);
    rejected(&value);
}
