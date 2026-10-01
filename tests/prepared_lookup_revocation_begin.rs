use crowsi_credential_authority_contracts::*;
use ed25519_dalek::SigningKey;
use ihat_identity_assertion_contracts::{AuthorityCommand, AuthorityResult, ResponseOutcome};

use crate::{
    endpoint_revocation_support::refresh,
    endpoint_revocation_values::{actor, identity_exchange},
    prepared_lookup_revocation_support::{request, response, sign, verify},
    prepared_lookup_support::{response as target_response, target_request},
};

#[test]
fn approval_lookup_requires_one_exact_live_stored_begin() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let request = request();
    let mut valid = response(&request);
    sign(&mut valid, &key);
    verify(&valid, &request, &key).expect("stored source Begin");
    for case in 0..6 {
        let mut changed = valid.clone();
        match case {
            0 => changed.revocation_begin_exchange = None,
            1 => wrong_prepared_binding(&mut changed),
            2 => {
                changed.revocation_begin_exchange =
                    Some(identity_exchange(&actor("device-a", 'a')));
            }
            3 => expire_begin(&mut changed),
            4 => future_begin(&mut changed),
            _ => outlive_begin(&mut changed),
        }
        sign(&mut changed, &key);
        assert_eq!(
            verify(&changed, &request, &key),
            Err(ContractError::Invalid),
            "case {case}"
        );
    }
}

#[test]
fn lookup_begin_field_is_required_closed_and_approval_only() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let request = request();
    let mut approval = response(&request);
    sign(&mut approval, &key);
    let mut missing = serde_json::to_value(&approval).expect("json");
    missing
        .as_object_mut()
        .expect("object")
        .remove("revocation_begin_exchange");
    strict_rejected(&missing, "required field");
    let mut legacy = missing;
    legacy["schema"] =
        serde_json::json!("crowsi://credential-authority/endpoint-prepared-lookup-response/v2");
    strict_rejected(&legacy, "legacy v2 response");
    let mut unknown = serde_json::to_value(&approval).expect("json");
    unknown
        .as_object_mut()
        .expect("object")
        .insert("unknown".into(), serde_json::json!(true));
    strict_rejected(&unknown, "unknown field");
    let target = target_request();
    let mut changed = target_response(&target);
    changed.revocation_begin_exchange = approval.revocation_begin_exchange;
    sign(&mut changed, &key);
    assert_eq!(
        verify_endpoint_prepared_lookup_response_at(
            &changed,
            &target,
            "lookup-key",
            &hex::encode(key.verifying_key().to_bytes()),
            110,
        ),
        Err(ContractError::Invalid)
    );
    let mut changed = target_response(&target);
    changed.pre_final_acceptance_request_sha256 = Some("55".repeat(32));
    sign(&mut changed, &key);
    assert_eq!(
        verify_endpoint_prepared_lookup_response_at(
            &changed,
            &target,
            "lookup-key",
            &hex::encode(key.verifying_key().to_bytes()),
            110,
        ),
        Err(ContractError::Invalid)
    );
}

fn wrong_prepared_binding(value: &mut EndpointPreparedLookupResponseV1) {
    let exchange = value
        .revocation_begin_exchange
        .as_mut()
        .expect("Begin exchange");
    let AuthorityCommand::BeginDeviceRevocation(command) = &mut exchange.request.command else {
        unreachable!()
    };
    command.target_device_id = "device-d".into();
    refresh(exchange);
}

fn expire_begin(value: &mut EndpointPreparedLookupResponseV1) {
    let exchange = value
        .revocation_begin_exchange
        .as_mut()
        .expect("Begin exchange");
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(result),
    } = &mut exchange.response.outcome
    else {
        unreachable!()
    };
    result.expires_at_epoch_s = 110;
}

fn future_begin(value: &mut EndpointPreparedLookupResponseV1) {
    value
        .revocation_begin_exchange
        .as_mut()
        .expect("Begin exchange")
        .response
        .issued_at_epoch_s = 111;
}

fn outlive_begin(value: &mut EndpointPreparedLookupResponseV1) {
    let exchange = value
        .revocation_begin_exchange
        .as_mut()
        .expect("Begin exchange");
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(result),
    } = &mut exchange.response.outcome
    else {
        unreachable!()
    };
    result.expires_at_epoch_s = 120;
}

fn strict_rejected(value: &serde_json::Value, case: &str) {
    assert_eq!(
        decode_endpoint_prepared_lookup_response_strict(&serde_json::to_vec(value).expect("wire")),
        Err(ContractError::Invalid),
        "{case}"
    );
}
