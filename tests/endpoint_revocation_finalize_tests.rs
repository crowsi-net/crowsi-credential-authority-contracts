use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    endpoint_revocation_exchanges::final_exchange, endpoint_revocation_support::source_envelope,
    management_support::signed_projection,
};

const NOW: u64 = 200;

#[test]
fn finalize_request_is_closed_and_correlated_with_the_stored_begin() {
    let (value, begin) = request();
    let wire = serde_json::to_vec(&value).expect("wire");
    assert_eq!(
        decode_endpoint_revocation_finalize_request_strict(&wire).expect("strict"),
        value
    );
    validate_endpoint_revocation_finalize_against_begin(&value, &begin)
        .expect("exact stored begin");

    let mut wrong_digest = value.clone();
    let ResponseOutcome::Committed {
        result: AuthorityResult::DeviceRevocation(result),
    } = &mut wrong_digest.final_revoke_exchange.response.outcome
    else {
        unreachable!()
    };
    result.target_digest = "99".repeat(32);
    assert_eq!(
        validate_endpoint_revocation_finalize_against_begin(&wrong_digest, &begin),
        Err(ContractError::Invalid)
    );

    let mut unknown = serde_json::to_value(value).expect("json");
    unknown["unknown"] = true.into();
    assert!(serde_json::from_value::<EndpointRevocationFinalizeRequestV1>(unknown).is_err());
}

#[test]
fn finalize_projection_binds_request_owner_peer_and_prepared_operation() {
    let (request, _) = request();
    let key = SigningKey::from_bytes(&[5_u8; 32]);
    let mut substituted = projection(&request, &key);
    verify(&substituted, &request, &key).expect("exact projection");
    substituted.current_device_ref = "device-b".into();
    resign(&mut substituted, &key);
    assert_eq!(
        verify(&substituted, &request, &key),
        Err(ContractError::Invalid)
    );

    let mut advanced = projection(&request, &key);
    {
        let ManagementProjectionBodyV2::Operation { operation } = &mut advanced.body else {
            unreachable!()
        };
        operation.state = ManagementOperationState::Completed;
        operation.state_revision = request.expected_state_revision + 9;
        operation.reason = None;
        operation.reconcile_digest = None;
        operation.actor = ActorRequirementV2 {
            role: RequiredActorRole::NoActor,
            required_actor_device_ref: None,
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        };
    }
    resign(&mut advanced, &key);
    verify(&advanced, &request, &key).expect("durable saga revision is monotonic");

    let ManagementProjectionBodyV2::Operation { operation } = &mut advanced.body else {
        unreachable!()
    };
    operation.state_revision = request.expected_state_revision + 1;
    resign(&mut advanced, &key);
    assert_eq!(
        verify(&advanced, &request, &key),
        Err(ContractError::Invalid)
    );
}

#[test]
fn fresh_pre_final_projection_recovers_only_while_the_exact_begin_is_live() {
    let envelope = accepted_source_envelope();
    let key = SigningKey::from_bytes(&[6_u8; 32]);
    let mut projection = pre_final_projection(&envelope, &key, NOW + 31);
    verify_pre_final(&projection, &envelope, &key, NOW + 32).expect("historic acceptance");

    projection.current_session_ref = "session-substituted".into();
    resign(&mut projection, &key);
    assert_eq!(
        verify_pre_final(&projection, &envelope, &key, NOW + 32),
        Err(ContractError::Invalid)
    );

    let expired = pre_final_projection(&envelope, &key, NOW + 301);
    assert_eq!(
        verify_pre_final(&expired, &envelope, &key, NOW + 302),
        Err(ContractError::Invalid)
    );
}

include!("endpoint_revocation_finalize_test_support.rs");
