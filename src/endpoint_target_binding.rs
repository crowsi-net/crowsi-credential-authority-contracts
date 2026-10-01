use ihat_identity_assertion_contracts::{FreshUvV1, IdentityEvidenceMetadata};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementIntentV2, SignedTargetDeviceProofV2,
    endpoint_operation_digest,
};

/// Checks every closed target proof field against the target endpoint identity and operation.
///
/// # Errors
/// Rejects actor, owner, scope, key, time, nonce, custody, or signature-shape substitution.
pub fn context(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    value: &SignedTargetDeviceProofV2,
) -> Result<(), ContractError> {
    let ManagementIntentV2::DeviceTransfer {
        service_id,
        target_device_ref,
        ..
    } = &prepared.intent
    else {
        return Err(ContractError::Invalid);
    };
    let binding = &value.binding;
    let lifetime = binding
        .expires_at_epoch_s
        .checked_sub(binding.issued_at_epoch_s);
    let exact = binding.schema == "crowsi://identity/target-device-key-proof/v2"
        && binding.owner_ref == prepared.opaque_owner_ref
        && binding.operation_id == prepared.operation_id
        && binding.challenge_digest_sha256 == endpoint_operation_digest(prepared)?
        && binding.source_device_ref == prepared.source_device_ref
        && binding.target_device_ref == *target_device_ref
        && binding.target_device_ref == identity.assertion.device_id
        && binding.service_id == *service_id
        && binding.pairwise_subject == identity.assertion.pairwise_subject
        && binding.device_proof_key_ref == identity.assertion.device_proof_key_ref
        && !binding.custody_revision.is_empty()
        && binding.custody_revision.len() <= 128
        && binding.status_nonce == identity.current_status.nonce
        && lifetime.is_some_and(|seconds| (1..=60).contains(&seconds))
        && binding.nonce == prepared.nonce
        && binding.key_id == binding.device_proof_key_ref
        && value.signature_hex.len() == 128
        && value
            .signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    exact.then_some(()).ok_or(ContractError::Invalid)
}

/// Links target proof issuance to Finish, the subsequent current identity, and operation expiry.
///
/// # Errors
/// Rejects proof issuance before current identity or proof validity beyond any trusted input.
pub fn freshness(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    value: &SignedTargetDeviceProofV2,
) -> Result<(), ContractError> {
    let binding = &value.binding;
    let exact = identity.assertion.issued_at_epoch_s == identity.current_status.issued_at_epoch_s
        && fresh.issued_at_epoch_s <= identity.assertion.issued_at_epoch_s
        && fresh.issued_at_epoch_s <= identity.current_status.issued_at_epoch_s
        && identity.assertion.issued_at_epoch_s <= binding.issued_at_epoch_s
        && identity.current_status.issued_at_epoch_s <= binding.issued_at_epoch_s
        && binding.expires_at_epoch_s <= fresh.expires_at_epoch_s
        && binding.expires_at_epoch_s <= identity.assertion.expires_at_epoch_s
        && binding.expires_at_epoch_s <= identity.current_status.expires_at_epoch_s
        && binding.expires_at_epoch_s <= prepared.expires_at_epoch_s;
    exact.then_some(()).ok_or(ContractError::Invalid)
}

/// Verifies the exact target actor context, trusted time, pinned key, and CNG digest signature.
///
/// # Errors
/// Rejects an untrusted key, stale proof, context substitution, or invalid Ed25519 signature.
pub fn verify_at(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    value: &SignedTargetDeviceProofV2,
    expected_key_id: &str,
    public_key_hex: &str,
    now_epoch_s: u64,
) -> Result<(), ContractError> {
    context(identity, prepared, value)?;
    freshness(identity, prepared, fresh, value)?;
    let binding = &value.binding;
    if binding.key_id != expected_key_id
        || now_epoch_s < binding.issued_at_epoch_s
        || now_epoch_s >= binding.expires_at_epoch_s
    {
        return Err(ContractError::Invalid);
    }
    crate::management_crypto::verify(
        public_key_hex,
        &value.signature_hex,
        &crate::target_device_proof_digest(binding)?,
    )
}
