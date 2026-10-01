use crowsi_credential_authority_contracts::*;

use crate::endpoint_revocation_values::{
    actor, assertion, browser, finish_uv_exchange, fresh, identity_exchange, sref,
};
use crate::endpoint_session_exchanges::{approval, begin, final_revoke};

pub(crate) fn envelope(actor_device: &str) -> EndpointManagementEnvelopeV2 {
    let identity = actor(actor_device, actor_device.chars().last().expect("actor"));
    let prepared = prepared();
    let actor_fresh = fresh(
        &identity,
        &prepared,
        "approval-uv",
        &format!("credential-{actor_device}"),
    );
    let finish_uv_exchange = finish_uv_exchange(&actor_fresh);
    let source_fresh = fresh(
        &actor("device-a", 'a'),
        &prepared,
        "source-uv",
        "credential-a",
    );
    let begin = begin(&prepared, &source_fresh);
    let approval = approval(&prepared, actor_device, &begin);
    let final_revoke = final_revoke(&prepared);
    let identity_exchange = identity_exchange(&identity);
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser(
            "session-approval",
            ManagementCommandV2::ApproveRevocation {
                operation_id: prepared.operation_id.clone(),
                expected_state_revision: 4,
                attempt_id: actor_fresh.attempt_id.clone(),
                assertion: assertion(&format!("credential-{actor_device}")),
            },
        ),
        evidence: EndpointManagementEvidenceV2::IndependentApprove {
            identity_exchange,
            prepared,
            finish_uv_exchange,
            revocation_ceremony: RevocationIndependentCeremonyV1 {
                begin,
                approval,
                final_revoke,
            },
        },
    }
}

fn prepared() -> EndpointPreparedOperationV2 {
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: sref('a'),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: "identity-nonce-device-a".into(),
        nonce: "session-prepared-nonce".into(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 400,
        intent: ManagementIntentV2::SessionRevocation {
            service_id: "service-a".into(),
            target_session_ref: sref('b'),
            expected_session_revocation_epoch: 1,
            expected_snapshot_revision: 1,
            nonce: "intent-nonce".into(),
        },
        revocation: Some(RevocationRequirementsV2 {
            target_device_ref: "device-b".into(),
            required_approval_authority_ref: Some("recovery-authority-c".into()),
            finalization_authority_id: "runtime-revocation-key".into(),
            expected_revoked_session_count: None,
        }),
    };
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    value
}
