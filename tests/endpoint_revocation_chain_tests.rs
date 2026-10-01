use crowsi_credential_authority_contracts::*;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::canonical_response;

use crate::endpoint_revocation_support::independent_envelope;

#[test]
fn independent_ceremony_requires_nondecreasing_generation_and_issued_time() {
    let mut increasing = independent_envelope();
    let increasing_ceremony = ceremony(&mut increasing);
    increasing_ceremony.approval.response.config_generation = 3;
    increasing_ceremony.final_revoke.response.config_generation = 4;
    accepted(&increasing);
    for case in 0..5 {
        let mut value = independent_envelope();
        let ceremony = ceremony(&mut value);
        match case {
            0 => ceremony.approval.response.config_generation = 1,
            1 => ceremony.final_revoke.response.config_generation = 1,
            2 => set_issued(&mut ceremony.approval, 99),
            3 => set_issued(&mut ceremony.final_revoke, 101),
            _ => set_issued(&mut ceremony.final_revoke, 400),
        }
        rejected(&value);
    }
}

#[test]
fn independently_valid_rotated_approval_or_final_key_is_rejected() {
    let rotated_key = SigningKey::from_bytes(&[7_u8; 32]);
    for approval in [true, false] {
        let mut value = independent_envelope();
        let exchange = if approval {
            &mut ceremony(&mut value).approval
        } else {
            &mut ceremony(&mut value).final_revoke
        };
        let command_type = if approval {
            "approve_revocation"
        } else {
            "revoke_device_by_ref"
        };
        exchange.response.key_id = "rotated-authority-key".into();
        exchange.response.signature = hex::encode(
            rotated_key
                .sign(&canonical_response(&exchange.response).expect("canonical"))
                .to_bytes(),
        );
        let issued_at_epoch_s = exchange.response.issued_at_epoch_s;
        verify_authority_exchange_at(
            exchange,
            command_type,
            2,
            "rotated-authority-key",
            &hex::encode(rotated_key.verifying_key().to_bytes()),
            issued_at_epoch_s,
        )
        .expect("rotated exchange is independently signed and current");
        rejected(&value);
    }
}

fn ceremony(value: &mut EndpointManagementEnvelopeV2) -> &mut RevocationIndependentCeremonyV1 {
    let EndpointManagementEvidenceV2::IndependentApprove {
        revocation_ceremony,
        ..
    } = &mut value.evidence
    else {
        unreachable!()
    };
    revocation_ceremony
}

fn set_issued(value: &mut SignedAuthorityExchangeV1, issued_at_epoch_s: u64) {
    value.response.issued_at_epoch_s = issued_at_epoch_s;
    value.response.expires_at_epoch_s = issued_at_epoch_s + 30;
}

fn accepted(value: &EndpointManagementEnvelopeV2) {
    decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire"))
        .expect("valid ceremony");
}

fn rejected(value: &EndpointManagementEnvelopeV2) {
    assert_eq!(
        decode_endpoint_management_envelope_strict(&serde_json::to_vec(value).expect("wire")),
        Err(ContractError::Invalid)
    );
}
