use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    endpoint_revocation_support::source_envelope, endpoint_revocation_values::browser,
    management_support::signed_projection,
};

const NOW: u64 = 500;

#[test]
fn historic_cancel_projection_is_fresh_but_binds_the_exact_accepted_envelope() {
    let envelope = cancel_envelope();
    let key = SigningKey::from_bytes(&[5_u8; 32]);
    let mut projection = cancel_projection(&envelope, &key);
    verify(&projection, &envelope, &key).expect("historic exact cancel");

    projection.current_session_ref = "sref_substituted".into();
    resign(&mut projection, &key);
    assert_eq!(
        verify(&projection, &envelope, &key),
        Err(ContractError::Invalid)
    );

    let mut substituted = envelope.clone();
    substituted.browser_request.request_id = "cancel-substituted".into();
    assert_eq!(
        verify(&cancel_projection(&envelope, &key), &substituted, &key),
        Err(ContractError::Invalid)
    );
}

include!("endpoint_cancel_recovery_support.rs");
