use crowsi_credential_authority_contracts::*;

use crate::{endpoint_revocation_values::fresh, endpoint_target_context::fixture};

#[test]
fn target_proof_is_after_finish_and_current_identity_and_expires_first() {
    let (identity, prepared, mut proof) = fixture();
    let fresh = fresh(&identity, &prepared, "target-uv", "credential-b");
    proof.binding.expires_at_epoch_s = fresh.expires_at_epoch_s;
    validate_target_device_proof_freshness(&identity, &prepared, &fresh, &proof)
        .expect("Finish <= current identity <= target proof");

    for case in 0..3 {
        let mut changed_identity = identity.clone();
        let mut changed_proof = proof.clone();
        match case {
            0 => {
                changed_identity.assertion.issued_at_epoch_s = fresh.issued_at_epoch_s - 1;
                changed_identity.current_status.issued_at_epoch_s = fresh.issued_at_epoch_s - 1;
            }
            1 => changed_proof.binding.issued_at_epoch_s -= 1,
            _ => changed_proof.binding.expires_at_epoch_s = fresh.expires_at_epoch_s + 1,
        }
        assert_eq!(
            validate_target_device_proof_freshness(
                &changed_identity,
                &prepared,
                &fresh,
                &changed_proof
            ),
            Err(ContractError::Invalid),
            "case {case}"
        );
    }
}
