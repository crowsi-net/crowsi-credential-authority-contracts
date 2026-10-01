use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::*;

use crate::endpoint_revocation_exchanges::{approval, begin, final_exchange};
use crate::endpoint_revocation_values::*;

pub(crate) fn prepared(target: &str) -> EndpointPreparedOperationV2 {
    let cross = target != "device-a";
    let mut value = EndpointPreparedOperationV2 {
        operation_id: "finalize-a".into(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: sref('a'),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: "identity-nonce-device-a".into(),
        nonce: "prepared-nonce".into(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 400,
        intent: ManagementIntentV2::DeviceRevocation {
            service_id: "service-a".into(),
            target_device_ref: target.into(),
            expected_device_revocation_epoch: 1,
            expected_snapshot_revision: 1,
            nonce: "intent-nonce".into(),
        },
        revocation: Some(RevocationRequirementsV2 {
            target_device_ref: target.into(),
            required_approval_authority_ref: cross.then(|| "recovery-authority-c".into()),
            finalization_authority_id: "runtime-revocation-key".into(),
            expected_revoked_session_count: Some(2),
        }),
    };
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    value
}

pub(crate) fn source_envelope(target: &str) -> EndpointManagementEnvelopeV2 {
    let identity = actor("device-a", 'a');
    let prepared = prepared(target);
    let fresh = fresh(&identity, &prepared, "source-uv", "credential-a");
    let finish_uv_exchange = finish_uv_exchange(&fresh);
    let begin = begin(&prepared, &fresh, target != "device-a");
    let identity_exchange = identity_exchange(&identity);
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser(
            "request-source",
            ManagementCommandV2::SourceApprove {
                operation_id: prepared.operation_id.clone(),
                expected_state_revision: 1,
                attempt_id: fresh.attempt_id.clone(),
                assertion: assertion("credential-a"),
            },
        ),
        evidence: EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange,
            prepared,
            finish_uv_exchange,
            revocation_ceremony: Some(RevocationSourceCeremonyV1 {
                begin,
                final_revoke: None,
            }),
        },
    }
}

pub(crate) fn independent_envelope() -> EndpointManagementEnvelopeV2 {
    let identity = actor("device-c", 'c');
    let prepared = prepared("device-b");
    let actor_fresh = fresh(&identity, &prepared, "approval-uv", "credential-c");
    let finish_uv_exchange = finish_uv_exchange(&actor_fresh);
    let begin_fresh = fresh(
        &actor("device-a", 'a'),
        &prepared,
        "source-uv",
        "credential-a",
    );
    let begin = begin(&prepared, &begin_fresh, true);
    let approval = approval(&prepared, &identity, &begin);
    let final_revoke = final_exchange(&prepared, 103);
    let identity_exchange = identity_exchange(&identity);
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser(
            "request-approval",
            ManagementCommandV2::ApproveRevocation {
                operation_id: prepared.operation_id.clone(),
                expected_state_revision: 4,
                attempt_id: actor_fresh.attempt_id.clone(),
                assertion: assertion("credential-c"),
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

pub(crate) fn refresh(exchange: &mut SignedAuthorityExchangeV1) {
    let digest = command_digest(&exchange.request).expect("digest");
    for evidence in &mut exchange.request.evidence {
        if let AuthorityEvidence::Signed(value) = evidence {
            value.binding_sha256.clone_from(&digest);
        }
    }
    exchange.response.command_digest = digest;
}
