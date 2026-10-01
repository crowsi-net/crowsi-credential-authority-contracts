use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityRejectionCode, AuthorityResult, ResponseOutcome, command_digest,
};

use crate::{
    endpoint_actor_support::transfer_prepared,
    endpoint_revocation_support::source_envelope,
    endpoint_revocation_values::{actor, finish_uv_exchange, fresh, uv_options},
};

fn rejected(value: &EndpointManagementEnvelopeV2) {
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire")),
        Err(ContractError::Invalid)
    );
}

#[test]
fn finish_uv_request_is_exactly_bound_to_browser_webauthn_fields() {
    for case in 0..5 {
        let mut value = source_envelope("device-b");
        let EndpointManagementEvidenceV2::SourceApprove {
            finish_uv_exchange, ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        let AuthorityCommand::FinishFreshUserVerification(command) =
            &mut finish_uv_exchange.request.command
        else {
            unreachable!()
        };
        match case {
            0 => command.attempt_id.push('x'),
            1 => command.credential_id.push('x'),
            2 => command.client_data_json_base64url.push('x'),
            3 => command.authenticator_data_base64url.push('x'),
            _ => command.signature_der_base64url.push('x'),
        }
        finish_uv_exchange.response.command_digest =
            command_digest(&finish_uv_exchange.request).expect("digest");
        rejected(&value);
    }
}

#[test]
fn finish_uv_result_and_exchange_correlation_are_closed() {
    for case in 0..6 {
        let mut value = source_envelope("device-b");
        let EndpointManagementEvidenceV2::SourceApprove {
            finish_uv_exchange, ..
        } = &mut value.evidence
        else {
            unreachable!()
        };
        match case {
            0 => finish_uv_exchange.request.evidence.push(dummy_evidence()),
            1 => finish_uv_exchange.response.request_id.push('x'),
            2 => finish_uv_exchange.response.command_digest.push('x'),
            3 => finish_uv_exchange.response.config_generation = 0,
            4 => {
                finish_uv_exchange.response.outcome = ResponseOutcome::Rejected {
                    code: AuthorityRejectionCode::EvidenceRejected,
                }
            }
            _ => {
                let ResponseOutcome::Committed {
                    result: AuthorityResult::FreshUvFinished { document },
                } = &mut finish_uv_exchange.response.outcome
                else {
                    unreachable!()
                };
                document.attempt_id.push('x');
            }
        }
        rejected(&value);
    }
}

#[test]
fn finish_uv_is_linked_to_the_exact_selected_begin_attempt() {
    let identity = actor("device-a", 'a');
    let prepared = transfer_prepared();
    let begin = uv_options(&identity, &prepared);
    let document = fresh(&identity, &prepared, "source-uv", "credential-device-a");
    let finish = finish_uv_exchange(&document);
    let browser = ManagementCommandV2::SourceApprove {
        operation_id: prepared.operation_id,
        expected_state_revision: 2,
        attempt_id: document.attempt_id,
        assertion: crate::endpoint_revocation_values::assertion("credential-device-a"),
    };
    validate_finish_uv_continuity(&begin, &finish, &browser).expect("same begin and finish");
    for case in 0..3 {
        let mut other = begin.clone();
        let ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options),
        } = &mut other.response.outcome
        else {
            unreachable!()
        };
        match case {
            0 => options.attempt_id.push('x'),
            1 => options.challenge.push('x'),
            _ => options.command_binding_sha256 = "99".repeat(32),
        }
        assert_eq!(
            validate_finish_uv_continuity(&other, &finish, &browser),
            Err(ContractError::Invalid)
        );
    }
}

fn dummy_evidence() -> ihat_identity_assertion_contracts::AuthorityEvidence {
    ihat_identity_assertion_contracts::AuthorityEvidence::FreshUv(
        crate::endpoint_revocation_values::fresh(
            &crate::endpoint_revocation_values::actor("device-a", 'a'),
            &crate::endpoint_revocation_support::prepared("device-b"),
            "other-proof",
            "credential-a",
        ),
    )
}
