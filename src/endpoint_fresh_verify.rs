use ihat_identity_assertion_contracts::{
    FreshUvBinding, FreshUvV1, IdentityEvidenceMetadata, verify_fresh_uv_at,
};

use crate::{ContractError, EndpointPreparedOperationV2, ManagementCommandV2};

pub struct EndpointFreshUvTrustV2<'a> {
    pub account_binding_sha256: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub now_epoch_s: u64,
}

/// Verifies fresh UV against browser, operation, current actor, account, key, and trusted time.
///
/// # Errors
/// Rejects a stale, wrong-actor, wrong-operation, wrong-account, or invalidly signed UV document.
pub fn verify(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    value: &FreshUvV1,
    command: &ManagementCommandV2,
    trust: &EndpointFreshUvTrustV2<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_identity_operation::fresh(identity, prepared, value, command)?;
    verify_fresh_uv_at(
        value,
        &FreshUvBinding {
            proof_id: &value.proof_id,
            credential_id: &value.credential_id,
            authenticator_key_fingerprint: &value.authenticator_key_fingerprint,
            kind: value.kind,
            challenge: &value.challenge,
            attempt_id: &value.attempt_id,
            identity_nonce: &value.identity_nonce,
            source_device_id: &identity.assertion.device_id,
            service_id: &identity.assertion.service_id,
            pairwise_subject: &identity.assertion.pairwise_subject,
            session_ref: &identity.assertion.session_ref,
            operation_digest_sha256: &crate::endpoint_operation_digest(prepared)?,
            subject_epoch: identity.assertion.revocation_epochs.subject,
            service_epoch: identity.assertion.revocation_epochs.service,
            device_epoch: identity.assertion.revocation_epochs.device,
            session_epoch: identity.assertion.revocation_epochs.session,
            account_binding_sha256: trust.account_binding_sha256,
        },
        trust.key_id,
        trust.public_key_hex,
        trust.now_epoch_s,
    )
    .map_err(|_| ContractError::Invalid)
}
