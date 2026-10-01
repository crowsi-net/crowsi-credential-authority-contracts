use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::prepared_lookup_support::{response, target_request};

const NOW: u64 = 110;

#[test]
fn e2e_17_prepared_lookup_binds_request_actor_operation_and_fresh_signature() {
    // E2E-17: endpoint-only prepared lookup is exact and never browser supplied.
    let key = SigningKey::from_bytes(&[8_u8; 32]);
    let request = target_request();
    let mut response = response(&request);
    response.signature = hex::encode(
        key.sign(&canonical_endpoint_prepared_lookup_response(&response).expect("canonical"))
            .to_bytes(),
    );
    let wire = serde_json::to_vec(&response).expect("wire");
    let decoded = decode_endpoint_prepared_lookup_response_strict(&wire).expect("strict");
    verify_endpoint_prepared_lookup_response_at(
        &decoded,
        &request,
        "lookup-key",
        &hex::encode(key.verifying_key().to_bytes()),
        NOW,
    )
    .expect("exact response");
    for mutation in [
        wrong_request,
        wrong_actor,
        wrong_session,
        wrong_epoch,
        wrong_operation,
    ] {
        let mut changed = response.clone();
        mutation(&mut changed);
        changed.signature = hex::encode(
            key.sign(&canonical_endpoint_prepared_lookup_response(&changed).expect("canonical"))
                .to_bytes(),
        );
        assert_eq!(
            verify_endpoint_prepared_lookup_response_at(
                &changed,
                &request,
                "lookup-key",
                &hex::encode(key.verifying_key().to_bytes()),
                NOW
            ),
            Err(ContractError::Invalid)
        );
    }
    for mutation in [wrong_prepared_expiry, wrong_prepared_source_nonce] {
        let mut changed = response.clone();
        mutation(&mut changed);
        changed.signature = hex::encode(
            key.sign(&canonical_endpoint_prepared_lookup_response(&changed).expect("canonical"))
                .to_bytes(),
        );
        assert_eq!(
            verify_endpoint_prepared_lookup_response_at(
                &changed,
                &request,
                "lookup-key",
                &hex::encode(key.verifying_key().to_bytes()),
                NOW
            ),
            Err(ContractError::Invalid)
        );
    }
    response.expires_at_epoch_s = NOW;
    response.signature = hex::encode(
        key.sign(&canonical_endpoint_prepared_lookup_response(&response).expect("canonical"))
            .to_bytes(),
    );
    assert_eq!(
        verify_endpoint_prepared_lookup_response_at(
            &response,
            &request,
            "lookup-key",
            &hex::encode(key.verifying_key().to_bytes()),
            NOW
        ),
        Err(ContractError::Invalid)
    );
}

#[test]
fn prepared_lookup_rejects_wrong_phase_unknown_fields_and_oversize() {
    let mut request = target_request();
    request.phase = EndpointPreparedLookupPhaseV1::Approval;
    let key = SigningKey::from_bytes(&[8_u8; 32]);
    let mut response = response(&request);
    response.signature = hex::encode(
        key.sign(&canonical_endpoint_prepared_lookup_response(&response).expect("canonical"))
            .to_bytes(),
    );
    assert_eq!(
        verify_endpoint_prepared_lookup_response_at(
            &response,
            &request,
            "lookup-key",
            &hex::encode(key.verifying_key().to_bytes()),
            NOW
        ),
        Err(ContractError::Invalid)
    );
    let mut wire = serde_json::to_value(target_request()).expect("json");
    wire.as_object_mut()
        .expect("object")
        .insert("prepared".into(), serde_json::json!({}));
    assert_eq!(
        decode_endpoint_prepared_lookup_request_strict(&serde_json::to_vec(&wire).expect("wire")),
        Err(ContractError::Invalid)
    );
    assert_eq!(
        decode_endpoint_prepared_lookup_request_strict(&vec![b' '; 262_145]),
        Err(ContractError::Invalid)
    );
}

fn wrong_request(value: &mut EndpointPreparedLookupResponseV1) {
    value.request_id.push('x');
}
fn wrong_actor(value: &mut EndpointPreparedLookupResponseV1) {
    value.actor_device_ref = "device-a".into();
}
fn wrong_session(value: &mut EndpointPreparedLookupResponseV1) {
    value.actor_session_ref = format!("sref_{}", "c".repeat(64));
}
fn wrong_epoch(value: &mut EndpointPreparedLookupResponseV1) {
    value.device_revocation_epoch += 1;
}
fn wrong_operation(value: &mut EndpointPreparedLookupResponseV1) {
    value.operation.operation_id.push('x');
}
fn wrong_prepared_expiry(value: &mut EndpointPreparedLookupResponseV1) {
    value.prepared.expires_at_epoch_s -= 1;
}
fn wrong_prepared_source_nonce(value: &mut EndpointPreparedLookupResponseV1) {
    value.prepared.source_identity_nonce.push('x');
}
