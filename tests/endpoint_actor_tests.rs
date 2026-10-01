use crowsi_credential_authority_contracts::*;

use crate::endpoint_actor_support::{actor_options, reconcile, source_options};

fn accepted(value: &EndpointManagementEnvelopeV2) -> bool {
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire")).is_ok()
}

#[test]
fn target_options_are_only_issued_to_b_and_approval_options_only_to_independent_c() {
    assert!(accepted(&actor_options("device-b", false)));
    assert!(accepted(&actor_options("device-c", true)));
    for actor in ["device-a", "device-c"] {
        assert!(
            !accepted(&actor_options(actor, false)),
            "target actor {actor}"
        );
    }
    for actor in ["device-a", "device-b"] {
        assert!(
            !accepted(&actor_options(actor, true)),
            "approval actor {actor}"
        );
    }
}

#[test]
fn destructive_reconcile_uses_a_current_same_owner_non_source_non_target_device() {
    assert!(accepted(&reconcile("device-c")));
    assert!(!accepted(&reconcile("device-a")));
    assert!(!accepted(&reconcile("device-b")));
    let mut other_owner = reconcile("device-c");
    let EndpointManagementEvidenceV2::Reconcile {
        identity_exchange, ..
    } = &mut other_owner.evidence
    else {
        unreachable!()
    };
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::IdentityEvidence(identity),
    } = &mut identity_exchange.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.pairwise_subject = "other-owner".into();
    identity.current_status.pairwise_subject = "other-owner".into();
    assert!(!accepted(&other_owner));
}

#[test]
fn source_options_rejects_missing_or_unresolved_revocation_requirements() {
    let value = source_options();
    assert!(accepted(&value));
    let mut missing = value.clone();
    let EndpointManagementEvidenceV2::SourceOptions { prepared, .. } = &mut missing.evidence else {
        unreachable!()
    };
    prepared.revocation = None;
    assert!(!accepted(&missing));
    let mut target_substitution = value;
    let EndpointManagementEvidenceV2::SourceOptions { prepared, .. } =
        &mut target_substitution.evidence
    else {
        unreachable!()
    };
    prepared
        .revocation
        .as_mut()
        .expect("requirements")
        .target_device_ref = "device-c".into();
    assert!(!accepted(&target_substitution));
    for case in 0..3 {
        let mut malformed = source_options();
        let EndpointManagementEvidenceV2::SourceOptions { prepared, .. } = &mut malformed.evidence
        else {
            unreachable!()
        };
        let requirements = prepared.revocation.as_mut().expect("requirements");
        match case {
            0 => requirements.required_approval_authority_ref = None,
            1 => requirements.finalization_authority_id.clear(),
            _ => requirements.expected_revoked_session_count = None,
        }
        assert!(!accepted(&malformed), "case {case}");
    }
}
