use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    endpoint_actor_support::transfer_prepared,
    endpoint_revocation_values::{
        actor, assertion, browser, finish_uv_exchange, fresh, identity_exchange,
    },
    endpoint_source_current_support::{advance, options},
    prepared_lookup_support::response,
};

#[test]
fn source_approve_accepts_fresh_current_identity_for_the_selected_session() {
    let original = source_approve("device-a", 'a', 100);
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&original).expect("wire"))
        .expect("original source identity");
    let refreshed = source_approve("device-a", 'a', 140);
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&refreshed).expect("wire"))
        .expect("fresh current identity with a new nonce");
    let rotated = source_approve("device-a", 'd', 140);
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(&rotated).expect("wire")),
        Err(ContractError::Invalid)
    );
    let mut wrong_actor = source_approve("device-c", 'c', 140);
    let EndpointManagementEvidenceV2::SourceApprove { prepared, .. } = &mut wrong_actor.evidence
    else {
        unreachable!()
    };
    prepared.pairwise_subject = "psu_pairwise-a".into();
    assert_eq!(
        decode_endpoint_management_envelope_strict(
            &serde_json::to_vec(&wrong_actor).expect("wire")
        ),
        Err(ContractError::Invalid)
    );
}

#[test]
fn cancel_lookup_actor_rule_and_envelope_both_allow_current_rotated_source() {
    let mut identity = actor("device-a", 'e');
    advance(&mut identity, 145);
    let prepared = transfer_prepared();
    let identity_exchange = identity_exchange(&identity);
    let request = EndpointPreparedLookupRequestV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA.into(),
        request_id: "cancel-lookup-current-source".into(),
        operation_id: prepared.operation_id.clone(),
        expected_state_revision: 2,
        phase: EndpointPreparedLookupPhaseV1::Cancel,
        identity_exchange: identity_exchange.clone(),
    };
    let key = SigningKey::from_bytes(&[8_u8; 32]);
    for state in [
        ManagementOperationState::AwaitingTarget,
        ManagementOperationState::AwaitingTargetUv,
    ] {
        let mut lookup = response(&request);
        lookup.operation.state = state;
        lookup.operation.webauthn_options =
            (state == ManagementOperationState::AwaitingTargetUv).then(options);
        lookup.signature = hex::encode(
            key.sign(&canonical_endpoint_prepared_lookup_response(&lookup).expect("canonical"))
                .to_bytes(),
        );
        verify_endpoint_prepared_lookup_response_at(
            &lookup,
            &request,
            "lookup-key",
            &hex::encode(key.verifying_key().to_bytes()),
            110,
        )
        .expect("source can recover prepared and cancel target UV wait");
    }
    let value = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser(
            "cancel-current-source",
            ManagementCommandV2::Cancel {
                operation_id: prepared.operation_id.clone(),
                expected_state_revision: 2,
            },
        ),
        evidence: EndpointManagementEvidenceV2::Cancel {
            identity_exchange,
            prepared,
        },
    };
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&value).expect("wire"))
        .expect("current source cancel");
}

pub(crate) fn source_approve(
    device: &str,
    session: char,
    now: u64,
) -> EndpointManagementEnvelopeV2 {
    let mut identity = actor(device, session);
    identity.assertion.pairwise_subject = "psu_pairwise-a".into();
    identity.current_status.pairwise_subject = "psu_pairwise-a".into();
    let selected_identity = identity.clone();
    if now > 100 {
        advance(&mut identity, now);
    }
    let prepared = transfer_prepared();
    let mut fresh = fresh(
        &selected_identity,
        &prepared,
        "source-current-uv",
        "credential-a",
    );
    fresh.issued_at_epoch_s = now;
    fresh.expires_at_epoch_s = now + 20;
    let finish_uv_exchange = finish_uv_exchange(&fresh);
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser(
            "source-current-approve",
            ManagementCommandV2::SourceApprove {
                operation_id: prepared.operation_id.clone(),
                expected_state_revision: 2,
                attempt_id: fresh.attempt_id.clone(),
                assertion: assertion("credential-a"),
            },
        ),
        evidence: EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange: identity_exchange(&identity),
            prepared,
            finish_uv_exchange,
            revocation_ceremony: None,
        },
    }
}
