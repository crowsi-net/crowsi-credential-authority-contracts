use ihat_identity_assertion_contracts::{
    AssertionVerifier, IdentityEvidenceMetadata, current_status_matches_assertion,
    verify_assertion_at, verify_current_status_at,
};

use crate::ContractError;

pub struct EndpointIdentityTrustV2<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub assertion_key_id: &'a str,
    pub assertion_public_key_hex: &'a str,
    pub current_status_key_id: &'a str,
    pub current_status_public_key_hex: &'a str,
    pub now_epoch_s: u64,
}

/// Verifies current iHAT identity and status with distinct pinned signing roles.
///
/// # Errors
/// Rejects context, time, key-role alias, signature, or assertion/status substitution.
pub fn verify(
    value: &IdentityEvidenceMetadata,
    trust: &EndpointIdentityTrustV2<'_>,
) -> Result<(), ContractError> {
    if trust.assertion_key_id == trust.current_status_key_id
        || trust.assertion_public_key_hex == trust.current_status_public_key_hex
    {
        return Err(ContractError::Invalid);
    }
    let assertion = PinnedVerifier {
        key_id: trust.assertion_key_id,
        public_key_hex: trust.assertion_public_key_hex,
    };
    let status = PinnedVerifier {
        key_id: trust.current_status_key_id,
        public_key_hex: trust.current_status_public_key_hex,
    };
    verify_assertion_at(
        &value.assertion,
        &assertion,
        trust.issuer,
        trust.audience,
        trust.now_epoch_s,
    )
    .map_err(|_| ContractError::Invalid)?;
    verify_current_status_at(
        &value.current_status,
        &status,
        trust.issuer,
        trust.audience,
        trust.now_epoch_s,
    )
    .map_err(|_| ContractError::Invalid)?;
    current_status_matches_assertion(&value.current_status, &value.assertion)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

struct PinnedVerifier<'a> {
    key_id: &'a str,
    public_key_hex: &'a str,
}

impl AssertionVerifier for PinnedVerifier<'_> {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        key_id == self.key_id
            && crate::management_crypto::verify(self.public_key_hex, signature, payload).is_ok()
    }
}
