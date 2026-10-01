use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ContractError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDeviceProofBindingV2 {
    pub schema: String,
    pub owner_ref: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub operation_id: String,
    pub challenge_digest_sha256: String,
    pub source_device_ref: String,
    pub target_device_ref: String,
    pub device_proof_key_ref: String,
    pub custody_revision: String,
    pub status_nonce: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub nonce: String,
    pub key_id: String,
}

/// Hashes the closed target-device proof binding.
///
/// # Errors
/// Rejects a wrong schema or an unencodable document.
pub fn target_device_proof_digest(
    value: &TargetDeviceProofBindingV2,
) -> Result<[u8; 32], ContractError> {
    if value.schema != "crowsi://identity/target-device-key-proof/v2" {
        return Err(ContractError::Invalid);
    }
    let body = serde_json::to_vec(value).map_err(|_| ContractError::Invalid)?;
    let mut digest = Sha256::new();
    digest.update(b"CROWSI-TARGET-DEVICE-KEY-PROOF-V2\0");
    digest.update(body);
    Ok(digest.finalize().into())
}
