use crowsi_credential_authority_contracts::{
    ContractError, decode_endpoint_management_envelope_strict,
};

use crate::endpoint_session_support::envelope;

#[test]
fn target_session_device_b_cannot_approve_but_distinct_c_can() {
    let c = envelope("device-c");
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(&c).expect("wire"))
        .expect("independent C approves exact B session revocation");
    let b = envelope("device-b");
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(&b).expect("wire")),
        Err(ContractError::Invalid)
    );
    let a = envelope("device-a");
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(&a).expect("wire")),
        Err(ContractError::Invalid)
    );
}
