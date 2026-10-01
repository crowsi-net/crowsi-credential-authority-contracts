use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, AuthorityResult, IdentityEvidenceMetadata, ResponseOutcome,
};

use crate::endpoint_approval_fixture::{ApprovalFixture, fixture};

#[test]
fn submission_current_identity_may_change_only_nonce_and_time() {
    fixture().verify().expect("baseline");
    for case in 0..10 {
        let mut value = fixture();
        let identity = current_identity(&mut value);
        match case {
            0 => set_both(identity, |v| v.device_id = "device-b".into()),
            1 => set_both(identity, |v| {
                v.session_ref = format!("sref_{}", "b".repeat(64));
            }),
            2 => set_both(identity, |v| v.service_id = "service-b".into()),
            3 => set_both(identity, |v| v.pairwise_subject = "psu_other".into()),
            4 => {
                identity.assertion.revocation_epochs.subject += 1;
                identity.current_status.revocation_epochs.subject += 1;
            }
            5 => {
                identity.assertion.revocation_epochs.service += 1;
                identity.current_status.revocation_epochs.service += 1;
            }
            6 => {
                identity.assertion.revocation_epochs.device += 1;
                identity.current_status.revocation_epochs.device += 1;
            }
            7 => {
                identity.assertion.revocation_epochs.session += 1;
                identity.current_status.revocation_epochs.session += 1;
            }
            8 => {
                identity.assertion.device_posture.revision += 1;
                identity.current_status.device_posture.revision += 1;
            }
            _ => set_both(identity, |v| v.device_proof_key_ref = "proof-other".into()),
        }
        value.resign_current();
        assert!(value.verify().is_err(), "case {case}");
    }
}

#[test]
fn session_sender_role_and_selected_fresh_nonce_cannot_be_substituted() {
    for key_id in [
        "other-sender",
        "proof-device-a",
        "assertion-key",
        "status-key",
        "fresh-key",
        "authority-key",
    ] {
        let mut value = fixture();
        let AuthorityEvidence::Signed(sender) = &mut value.current.request.evidence[0] else {
            unreachable!()
        };
        sender.key_id = key_id.into();
        value.resign_current();
        assert!(value.verify().is_err(), "sender {key_id}");
    }
    let mut fingerprint = fixture();
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) =
        &mut fingerprint.current.request.command
    else {
        unreachable!()
    };
    command.session_sender_key_fingerprint = "77".repeat(32);
    fingerprint.resign_current();
    assert!(fingerprint.verify().is_err());

    let mut nonce = fixture();
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvFinished { document },
    } = &mut nonce.finish.response.outcome
    else {
        unreachable!()
    };
    document.identity_nonce = "other-selected-nonce".into();
    nonce.resign_finish();
    assert!(nonce.verify().is_err());
}

#[test]
fn finish_and_current_authority_signatures_are_mandatory() {
    let mut finish = fixture();
    finish.finish.response.signature = "00".repeat(64);
    assert!(finish.verify().is_err());
    let mut current = fixture();
    current.current.response.signature = "00".repeat(64);
    assert!(current.verify().is_err());
}

fn current_identity(value: &mut ApprovalFixture) -> &mut IdentityEvidenceMetadata {
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut value.current.response.outcome
    else {
        unreachable!()
    };
    identity
}

fn set_both(
    identity: &mut IdentityEvidenceMetadata,
    mut update: impl FnMut(&mut ihat_identity_assertion_contracts::DeviceIdentityAssertionV1),
) {
    update(&mut identity.assertion);
    let mut assertion = identity.assertion.clone();
    update(&mut assertion);
    identity.current_status.service_id = assertion.service_id;
    identity.current_status.pairwise_subject = assertion.pairwise_subject;
    identity.current_status.device_id = assertion.device_id;
    identity.current_status.session_ref = assertion.session_ref;
    identity.current_status.device_proof_key_ref = assertion.device_proof_key_ref;
}
