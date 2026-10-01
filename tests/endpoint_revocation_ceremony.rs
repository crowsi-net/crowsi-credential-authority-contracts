use crowsi_credential_authority_contracts::*;

use crate::endpoint_revocation_support::{independent_envelope, source_envelope};

#[test]
fn source_approval_only_preauthorizes_final_for_self_and_cross_device_revocation() {
    let self_revoke = source_envelope("device-a");
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&self_revoke).expect("wire"))
        .expect("self revoke");
    validate_revocation_ceremony_at(&self_revoke.evidence, 399).expect("current ceremony");
    assert_eq!(
        validate_revocation_ceremony_at(&self_revoke.evidence, 400),
        Err(ContractError::Invalid)
    );

    let cross = source_envelope("device-b");
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&cross).expect("wire"))
        .expect("await independent approval");
    let mut illegal_final = cross;
    let EndpointManagementEvidenceV2::SourceApprove {
        revocation_ceremony: Some(ceremony),
        ..
    } = &mut illegal_final.evidence
    else {
        unreachable!()
    };
    let EndpointManagementEvidenceV2::IndependentApprove {
        revocation_ceremony: independent,
        ..
    } = independent_envelope().evidence
    else {
        unreachable!()
    };
    ceremony.final_revoke = Some(independent.final_revoke);
    assert_eq!(
        decode_endpoint_management_envelope_strict(
            &serde_json::to_vec(&illegal_final).expect("wire")
        ),
        Err(ContractError::Invalid)
    );
}

#[test]
fn a_to_b_revocation_requires_a_complete_c_approval_ceremony() {
    let value = independent_envelope();
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&value).expect("wire"))
        .expect("A begin, C approve, exact final");
    for missing in ["begin", "approval", "final_revoke"] {
        let mut json = serde_json::to_value(&value).expect("json");
        json["evidence"]["revocation_ceremony"]
            .as_object_mut()
            .expect("ceremony")
            .remove(missing);
        assert!(serde_json::from_value::<EndpointManagementEnvelopeV2>(json).is_err());
    }
}

#[test]
fn source_or_target_device_cannot_supply_the_independent_approval() {
    for actor in ["device-a", "device-b"] {
        let mut value = independent_envelope();
        let EndpointManagementEvidenceV2::IndependentApprove {
            identity_exchange, ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
            result: ihat_identity_assertion_contracts::AuthorityResult::IdentityEvidence(identity),
        } = &mut identity_exchange.response.outcome
        else {
            unreachable!()
        };
        identity.assertion.device_id = actor.into();
        identity.current_status.device_id = actor.into();
        assert_eq!(
            decode_endpoint_management_envelope_strict(&serde_json::to_vec(&value).expect("wire")),
            Err(ContractError::Invalid)
        );
    }
}
