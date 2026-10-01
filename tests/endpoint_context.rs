use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, command_digest,
};

use crate::{
    endpoint_envelope::identity, endpoint_exchange::exchange,
    endpoint_management_values::identity_exchange,
};

fn envelope() -> EndpointManagementEnvelopeV2 {
    let identity = identity();
    let intent = ManagementIntentV2::DeviceTransfer {
        service_id: "service-a".into(),
        target_device_ref: "device-b".into(),
        credential_refs: vec!["credential-a".into()],
        expected_snapshot_revision: 1,
        nonce: "intent-nonce".into(),
    };
    let browser_request = ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "browser-a".into(),
        command: ManagementCommandV2::SourceOptions {
            intent: intent.clone(),
        },
    };
    let mut prepared = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: management_command_digest(&browser_request).expect("digest"),
        source_device_ref: "device-a".into(),
        source_session_ref: identity.assertion.session_ref.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: identity.assertion.nonce.clone(),
        nonce: "operation-nonce".into(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 130,
        intent,
        revocation: None,
    };
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let operation_digest = endpoint_operation_digest(&prepared).expect("operation digest");
    let mut uv_options = exchange("identity-options-a");
    let AuthorityCommand::BeginFreshUserVerification(command) = &mut uv_options.request.command
    else {
        unreachable!()
    };
    command.identity_nonce.clone_from(&identity.assertion.nonce);
    command
        .source_device_id
        .clone_from(&identity.assertion.device_id);
    command
        .service_id
        .clone_from(&identity.assertion.service_id);
    command
        .pairwise_subject
        .clone_from(&identity.assertion.pairwise_subject);
    command
        .session_ref
        .clone_from(&identity.assertion.session_ref);
    command
        .operation_digest_sha256
        .clone_from(&operation_digest);
    let epochs = &identity.assertion.revocation_epochs;
    command.subject_epoch = epochs.subject;
    command.service_epoch = epochs.service;
    command.device_epoch = epochs.device;
    command.session_epoch = epochs.session;
    let request_digest = command_digest(&uv_options.request).expect("digest");
    uv_options
        .response
        .command_digest
        .clone_from(&request_digest);
    if let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut uv_options.response.outcome
    {
        options.command_binding_sha256 = request_digest;
    }
    prepared.intent = match &browser_request.command {
        ManagementCommandV2::SourceOptions { intent } => intent.clone(),
        _ => unreachable!(),
    };
    let identity_exchange = identity_exchange(&identity);
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

#[test]
fn prepared_exchange_and_identity_actor_context_are_exact() {
    let value = envelope();
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&value).expect("wire"))
        .expect("exact context");
    for case in 0..4 {
        let mut wrong = value.clone();
        let EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange,
            prepared,
            uv_options,
        } = &mut wrong.evidence
        else {
            unreachable!()
        };
        match case {
            0 => prepared.source_device_ref = "device-b".into(),
            1 => {
                let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
                    result:
                        ihat_identity_assertion_contracts::AuthorityResult::IdentityEvidence(identity),
                } = &mut identity_exchange.response.outcome
                else {
                    unreachable!()
                };
                identity.current_status.session_ref = format!("sref_{}", "b".repeat(64));
            }
            2 => {
                if let AuthorityCommand::BeginFreshUserVerification(command) =
                    &mut uv_options.request.command
                {
                    command.source_device_id = "device-b".into();
                }
            }
            _ => {
                if let ResponseOutcome::Committed {
                    result: AuthorityResult::FreshUvBegun(options),
                } = &mut uv_options.response.outcome
                {
                    options.command_binding_sha256 =
                        endpoint_operation_digest(prepared).expect("operation digest");
                }
            }
        }
        if case == 2 {
            uv_options.response.command_digest =
                command_digest(&uv_options.request).expect("digest");
        }
        assert_eq!(
            decode_endpoint_management_envelope_strict(&serde_json::to_vec(&wrong).expect("wire")),
            Err(ContractError::Invalid)
        );
    }
}
