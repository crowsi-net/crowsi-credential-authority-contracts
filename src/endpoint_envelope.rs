use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ContractError, EndpointManagementEnvelopeV2, EndpointPreparedOperationV2};

pub const ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-management-envelope/v2";
pub const ENDPOINT_OPERATION_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-MANAGEMENT-OPERATION-V2\0";
const PHASE_ENVELOPE_DOMAIN: &[u8] = b"CROWSI-MANAGEMENT-PHASE-ENVELOPE-V2\0";

/// Returns the exact bare SHA-256 phase-envelope digest durably accepted by central.
///
/// # Errors
/// Rejects an invalid or unencodable closed envelope.
pub fn endpoint_management_phase_envelope_digest(
    value: &EndpointManagementEnvelopeV2,
) -> Result<String, ContractError> {
    crate::endpoint_envelope_validation::validate(value)?;
    let wire = serde_json::to_vec(value).map_err(|_| ContractError::Invalid)?;
    let mut digest = Sha256::new();
    digest.update(PHASE_ENVELOPE_DOMAIN);
    digest.update(wire);
    Ok(hex::encode(digest.finalize()))
}

/// Derives the one stable operation identifier from the immutable source intent.
///
/// # Errors
/// Rejects an unencodable prepared operation.
pub fn endpoint_operation_id(value: &EndpointPreparedOperationV2) -> Result<String, ContractError> {
    #[derive(Serialize)]
    struct OperationBinding<'a> {
        origin_command_digest_sha256: &'a str,
        source_device_ref: &'a str,
        source_session_ref: &'a str,
        pairwise_subject: &'a str,
        opaque_owner_ref: &'a str,
        source_identity_nonce: &'a str,
        nonce: &'a str,
        #[serde(rename = "intent")]
        operation_intent: &'a crate::ManagementIntentV2,
    }
    let wire = serde_json::to_vec(&OperationBinding {
        origin_command_digest_sha256: &value.origin_command_digest_sha256,
        source_device_ref: &value.source_device_ref,
        source_session_ref: &value.source_session_ref,
        pairwise_subject: &value.pairwise_subject,
        opaque_owner_ref: &value.opaque_owner_ref,
        source_identity_nonce: &value.source_identity_nonce,
        nonce: &value.nonce,
        operation_intent: &value.intent,
    })
    .map_err(|_| ContractError::Invalid)?;
    let mut digest = Sha256::new();
    digest.update(b"CROWSI-ENDPOINT-OPERATION-ID-V2\0");
    digest.update(wire);
    Ok(hex::encode(digest.finalize()))
}

/// Verifies a prepared operation against fresh endpoint identity and trusted time.
///
/// # Errors
/// Rejects stale, future, wrong-actor, or overlong prepared operations.
pub fn validate_endpoint_prepared_at(
    value: &EndpointPreparedOperationV2,
    identity: &IdentityEvidenceMetadata,
    now: u64,
) -> Result<(), ContractError> {
    crate::endpoint_envelope_validation::validate_prepared_shape(value)?;
    let exact = ihat_identity_assertion_contracts::current_status_matches_assertion(
        &identity.current_status,
        &identity.assertion,
    ) && value.source_identity_nonce == identity.assertion.nonce
        && value.source_device_ref == identity.assertion.device_id
        && value.source_session_ref == identity.assertion.session_ref
        && value.pairwise_subject == identity.assertion.pairwise_subject
        && intent_service(&value.intent) == identity.assertion.service_id
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 300
        && value.issued_at_epoch_s >= identity.assertion.issued_at_epoch_s;
    exact.then_some(()).ok_or(ContractError::Invalid)
}

fn intent_service(value: &crate::ManagementIntentV2) -> &str {
    match value {
        crate::ManagementIntentV2::DeviceTransfer { service_id, .. }
        | crate::ManagementIntentV2::DeviceRevocation { service_id, .. }
        | crate::ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    }
}

/// Computes the exact operation digest signed by iHAT fresh-UV and target custody.
///
/// # Errors
///
/// Rejects an unencodable prepared operation.
pub fn endpoint_operation_digest(
    value: &EndpointPreparedOperationV2,
) -> Result<String, ContractError> {
    let body = serde_json::to_vec(value).map_err(|_| ContractError::Invalid)?;
    let mut digest = Sha256::new();
    digest.update(ENDPOINT_OPERATION_DOMAIN);
    digest.update(body);
    Ok(hex::encode(digest.finalize()))
}

/// Decodes one bounded, closed endpoint-to-central management envelope.
///
/// # Errors
///
/// Rejects malformed, oversized, unknown-field, or command/evidence phase mismatch documents.
pub fn decode_endpoint_management_envelope_strict(
    wire: &[u8],
) -> Result<EndpointManagementEnvelopeV2, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value: EndpointManagementEnvelopeV2 =
        serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_envelope_validation::validate(&value)?;
    Ok(value)
}
