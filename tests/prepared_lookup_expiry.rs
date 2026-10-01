use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    endpoint_revocation_values::{actor, identity_exchange},
    prepared_lookup_support::{response, target_request},
};

const NOW: u64 = 110;

#[test]
fn expired_historic_prepared_is_allowed_only_for_cancel_and_reconcile() {
    let key = SigningKey::from_bytes(&[8_u8; 32]);
    let target = target_request();
    let mut target_response = response(&target);
    expire(&mut target_response);
    sign(&mut target_response, &key);
    assert_eq!(
        verify(&target_response, &target, &key),
        Err(ContractError::Invalid)
    );

    let mut cancel = target_request();
    cancel.request_id = "expired-cancel".into();
    cancel.phase = EndpointPreparedLookupPhaseV1::Cancel;
    cancel.identity_exchange = identity_exchange(&actor("device-a", 'a'));
    let mut cancel_response = response(&cancel);
    expire(&mut cancel_response);
    sign(&mut cancel_response, &key);
    verify(&cancel_response, &cancel, &key).expect("historic cancel cleanup");

    let mut reconcile = target_request();
    reconcile.request_id = "expired-reconcile".into();
    reconcile.phase = EndpointPreparedLookupPhaseV1::Reconcile;
    let mut reconcile_response = response(&reconcile);
    reconcile_response.operation.state = ManagementOperationState::Unknown;
    reconcile_response.operation.actor = ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: vec![],
    };
    reconcile_response.operation.reason = Some(ManagementReasonCode::ProviderOutcomeUnknown);
    reconcile_response.operation.reconcile_digest = Some("99".repeat(32));
    expire(&mut reconcile_response);
    sign(&mut reconcile_response, &key);
    verify(&reconcile_response, &reconcile, &key).expect("historic crash reconciliation");
}

fn expire(value: &mut EndpointPreparedLookupResponseV1) {
    value.prepared.expires_at_epoch_s = NOW - 2;
    value.operation.expires_at_epoch_s = NOW - 2;
}

fn sign(value: &mut EndpointPreparedLookupResponseV1, key: &SigningKey) {
    value.signature = hex::encode(
        key.sign(&canonical_endpoint_prepared_lookup_response(value).expect("canonical"))
            .to_bytes(),
    );
}

fn verify(
    value: &EndpointPreparedLookupResponseV1,
    request: &EndpointPreparedLookupRequestV1,
    key: &SigningKey,
) -> Result<(), ContractError> {
    verify_endpoint_prepared_lookup_response_at(
        value,
        request,
        "lookup-key",
        &hex::encode(key.verifying_key().to_bytes()),
        NOW,
    )
}
