use crowsi_credential_authority_contracts::*;

use crate::endpoint_revocation_support::prepared;
use crate::endpoint_revocation_values::{actor, browser, identity_exchange, uv_options};

pub(crate) fn actor_options(actor_device: &str, approval: bool) -> EndpointManagementEnvelopeV2 {
    let identity = actor(actor_device, actor_device.chars().last().expect("actor"));
    let prepared = if approval {
        prepared("device-b")
    } else {
        transfer_prepared()
    };
    let command = if approval {
        ManagementCommandV2::ApprovalOptions {
            operation_id: prepared.operation_id.clone(),
            expected_state_revision: 3,
        }
    } else {
        ManagementCommandV2::TargetOptions {
            operation_id: prepared.operation_id.clone(),
            expected_state_revision: 3,
        }
    };
    let uv_options = uv_options(&identity, &prepared);
    let identity_exchange = identity_exchange(&identity);
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser("actor-options", command),
        evidence: EndpointManagementEvidenceV2::ActorOptions {
            identity_exchange,
            prepared,
            uv_options,
        },
    }
}

pub(crate) fn reconcile(actor_device: &str) -> EndpointManagementEnvelopeV2 {
    let identity = actor(actor_device, actor_device.chars().last().expect("actor"));
    let prepared = prepared("device-b");
    let identity_exchange = identity_exchange(&identity);
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser(
            "reconcile-request",
            ManagementCommandV2::Reconcile {
                operation_id: prepared.operation_id.clone(),
                expected_state_revision: 5,
                reconcile_digest: "99".repeat(32),
            },
        ),
        evidence: EndpointManagementEvidenceV2::Reconcile {
            identity_exchange,
            prepared,
        },
    }
}

pub(crate) fn source_options() -> EndpointManagementEnvelopeV2 {
    let identity = actor("device-a", 'a');
    let mut prepared = prepared("device-b");
    let mut browser_request = browser(
        "source-options",
        ManagementCommandV2::SourceOptions {
            intent: prepared.intent.clone(),
        },
    );
    prepared.origin_command_digest_sha256 =
        management_command_digest(&browser_request).expect("digest");
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let uv_options = uv_options(&identity, &prepared);
    let identity_exchange = identity_exchange(&identity);
    browser_request.command = ManagementCommandV2::SourceOptions {
        intent: prepared.intent.clone(),
    };
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request,
        evidence: EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange,
            prepared,
            uv_options,
        },
    }
}

pub(crate) fn transfer_prepared() -> EndpointPreparedOperationV2 {
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: format!("sref_{}", "a".repeat(64)),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: "identity-nonce-device-a".into(),
        nonce: "transfer-nonce".into(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 400,
        intent: ManagementIntentV2::DeviceTransfer {
            service_id: "service-a".into(),
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_snapshot_revision: 1,
            nonce: "intent-nonce".into(),
        },
        revocation: None,
    };
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    value
}
