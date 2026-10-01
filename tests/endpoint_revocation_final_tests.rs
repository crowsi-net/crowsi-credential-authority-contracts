use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{AuthorityCommand, AuthorityResult, ResponseOutcome};

use crate::endpoint_revocation_support::{independent_envelope, refresh};

fn rejected(value: &EndpointManagementEnvelopeV2) {
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire")),
        Err(ContractError::Invalid)
    );
}

#[test]
fn final_device_revoke_command_cannot_change_target_epoch_or_authority() {
    for case in 0..6 {
        let mut value = independent_envelope();
        let EndpointManagementEvidenceV2::IndependentApprove {
            revocation_ceremony: ceremony,
            ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let AuthorityCommand::RevokeDeviceByRef(command) =
            &mut ceremony.final_revoke.request.command
        else {
            unreachable!()
        };
        match case {
            0 => command.command_id = "other-final".into(),
            1 => command.service_id = "service-b".into(),
            2 => command.pairwise_subject = "other-pairwise".into(),
            3 => command.target_device_id = "device-d".into(),
            4 => command.expected_device_epoch += 1,
            _ => command.authority_id = "other-authority".into(),
        }
        refresh(&mut ceremony.final_revoke);
        rejected(&value);
    }
}

#[test]
fn final_receipt_binds_begin_target_epoch_and_exact_revoked_child_count() {
    for case in 0..5 {
        let mut value = independent_envelope();
        let EndpointManagementEvidenceV2::IndependentApprove {
            revocation_ceremony: ceremony,
            ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let ResponseOutcome::Committed {
            result: AuthorityResult::DeviceRevocation(result),
        } = &mut ceremony.final_revoke.response.outcome
        else {
            unreachable!()
        };
        match case {
            0 => result.target_digest = "99".repeat(32),
            1 => result.previous_device_epoch = 2,
            2 => result.current_device_epoch = 1,
            3 => result.revoked_session_count = 3,
            _ => ceremony.final_revoke.response.issued_at_epoch_s = 400,
        }
        rejected(&value);
    }
}
