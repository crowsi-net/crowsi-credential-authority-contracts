use serde::{Deserialize, Serialize};

use crate::ContractError;

pub const OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1: &str =
    "crowsi://credential-authority/owner-recovery-custody-receipt/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerRecoveryCustodyStateV1 {
    Provisioned,
    Verified,
    Revoked,
}

/// Public projection from custody. Mnemonic words and derived private keys have
/// no serializable field and must remain inside the selected Crowsi provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoveryCustodyReceiptV1 {
    pub schema: String,
    pub recovery_id: String,
    pub subject_ref: String,
    pub custody_provider_ref: String,
    pub root_fingerprint_sha256: String,
    pub key_revision: u64,
    pub state: OwnerRecoveryCustodyStateV1,
    pub observed_at_epoch_s: u64,
}

impl OwnerRecoveryCustodyReceiptV1 {
    /// Validates only public proof metadata. It cannot validate or expose the phrase.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Invalid`] when a public identifier, revision,
    /// timestamp, schema, or SHA-256 fingerprint is malformed.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1
            || !token(&self.recovery_id)
            || !token(&self.subject_ref)
            || !token(&self.custody_provider_ref)
            || self.key_revision == 0
            || self.observed_at_epoch_s == 0
            || !self.root_fingerprint_sha256.starts_with("sha256:")
            || self.root_fingerprint_sha256.len() != 71
            || !self.root_fingerprint_sha256[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ContractError::Invalid);
        }
        Ok(())
    }
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'_' | b'-')
        })
}
