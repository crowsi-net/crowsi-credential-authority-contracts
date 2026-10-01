use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, AuthorityResult, ResponseOutcome, VerificationRole,
    command_digest,
};

use crate::{endpoint_envelope::identity, endpoint_management_values::identity_exchange};

fn envelope() -> EndpointManagementEnvelopeV2 {
    let identity = identity();
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: ManagementRequestV2 {
            schema: MANAGEMENT_REQUEST_SCHEMA.into(),
            request_id: "identity-exchange-passive".into(),
            command: ManagementCommandV2::Snapshot {
                service_id: identity.assertion.service_id.clone(),
            },
        },
        evidence: EndpointManagementEvidenceV2::Passive {
            identity_exchange: identity_exchange(&identity),
        },
    }
}

fn accepted(value: &EndpointManagementEnvelopeV2) -> bool {
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire")).is_ok()
}

#[test]
fn identity_is_only_accepted_from_exact_current_authority_exchange() {
    assert!(accepted(&envelope()));
    for case in 0..5 {
        let mut value = envelope();
        let EndpointManagementEvidenceV2::Passive { identity_exchange } = &mut value.evidence
        else {
            unreachable!()
        };
        match case {
            0 => identity_exchange.request.evidence.clear(),
            1 => {
                let AuthorityEvidence::Signed(sender) = &mut identity_exchange.request.evidence[0]
                else {
                    unreachable!()
                };
                sender.role = VerificationRole::DevicePossession;
            }
            2 => identity_exchange.response.config_generation = 0,
            3 => {
                identity_exchange.response.outcome = ResponseOutcome::Rejected {
                    code: ihat_identity_assertion_contracts::AuthorityRejectionCode::RequestInvalid,
                };
            }
            _ => substitute_device(identity_exchange),
        }
        assert!(!accepted(&value), "case {case}");
    }
}

#[test]
fn old_bare_identity_field_is_not_a_compatible_alias() {
    let value = envelope();
    let mut json = serde_json::to_value(&value).expect("json");
    let evidence = json["evidence"].as_object_mut().expect("evidence");
    let exchange = evidence.remove("identity_exchange").expect("exchange");
    evidence.insert(
        "identity".into(),
        exchange["response"]["outcome"]["result"].clone(),
    );
    assert!(serde_json::from_value::<EndpointManagementEnvelopeV2>(json).is_err());
}

#[test]
fn reconcile_has_no_unused_identity_outcome_alternate_surface() {
    let value = crate::endpoint_actor_support::reconcile("device-c");
    let mut json = serde_json::to_value(value).expect("json");
    json["evidence"]
        .as_object_mut()
        .expect("evidence")
        .insert("identity_outcome".into(), serde_json::Value::Null);
    assert!(serde_json::from_value::<EndpointManagementEnvelopeV2>(json).is_err());
}

fn substitute_device(value: &mut SignedAuthorityExchangeV1) {
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &mut value.request.command
    else {
        unreachable!()
    };
    command.device_id = "device-b".into();
    let digest = command_digest(&value.request).expect("digest");
    let AuthorityEvidence::Signed(sender) = &mut value.request.evidence[0] else {
        unreachable!()
    };
    sender.binding_sha256.clone_from(&digest);
    value.response.command_digest = digest;
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.device_id = "device-c".into();
    identity.current_status.device_id = "device-c".into();
}
