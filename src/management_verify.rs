use crate::{
    ContractError, ManagementProjectionBinding, ManagementProjectionV2,
    canonical_management_projection, management_crypto, management_validation,
};

/// Verifies an authority projection against exact endpoint context, revision, key, and time.
///
/// # Errors
///
/// Rejects malformed, substituted, rolled-back, stale, future, or incorrectly signed documents.
pub fn verify_management_projection_at(
    value: &ManagementProjectionV2,
    expected: &ManagementProjectionBinding<'_>,
    expected_key_id: &str,
    public_key_hex: &str,
    now_epoch_s: u64,
) -> Result<(), ContractError> {
    management_validation::projection(value)?;
    if value.request_id != expected.request_id
        || value.command_digest_sha256 != expected.command_digest_sha256
        || value.issuer != expected.issuer
        || value.audience != expected.audience
        || value.service_id != expected.service_id
        || value.pairwise_subject != expected.pairwise_subject
        || value.opaque_account_ref != expected.opaque_account_ref
        || value.current_device_ref != expected.current_device_ref
        || value.current_session_ref != expected.current_session_ref
        || value.subject_revocation_epoch != expected.subject_revocation_epoch
        || value.service_revocation_epoch != expected.service_revocation_epoch
        || value.device_revocation_epoch != expected.device_revocation_epoch
        || value.session_revocation_epoch != expected.session_revocation_epoch
        || value.device_posture_state != expected.device_posture_state
        || value.device_posture_revision != expected.device_posture_revision
        || value.device_proof_key_ref != expected.device_proof_key_ref
        || value.snapshot_revision < expected.minimum_snapshot_revision
        || value.key_id != expected_key_id
        || now_epoch_s < value.issued_at_epoch_s
        || now_epoch_s >= value.expires_at_epoch_s
    {
        return Err(ContractError::Invalid);
    }
    management_crypto::verify(
        public_key_hex,
        &value.signature,
        &canonical_management_projection(value)?,
    )
}
