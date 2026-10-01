use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointManagementEnvelopeV2, EndpointRevocationExecutionCancelRequestV1,
    EndpointRevocationExecutionCancellationV1,
};

const REQUEST_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-REVOCATION-EXECUTION-CANCEL-REQUEST-V1\0";
const CANCELLATION_DOMAIN: &[u8] = b"CROWSI-REVOCATION-EXECUTION-CANCELLATION-ID-V1\0";

/// Returns the domain-separated exact internal cancellation request digest.
///
/// # Errors
/// Rejects invalid or non-canonical requests.
pub fn endpoint_revocation_execution_cancel_request_digest(
    value: &EndpointRevocationExecutionCancelRequestV1,
) -> Result<String, ContractError> {
    crate::endpoint_revocation_execution_cancel_validation::request(value)?;
    digest(REQUEST_DOMAIN, value)
}

/// Returns the domain-separated exact browser Cancel envelope digest.
///
/// # Errors
/// Rejects an invalid or non-canonical envelope.
pub fn endpoint_revocation_cancel_envelope_digest(
    value: &EndpointManagementEnvelopeV2,
) -> Result<String, ContractError> {
    crate::endpoint_management_phase_envelope_digest(value)
}

/// Returns the immutable root-token cancellation identifier.
///
/// # Errors
/// Rejects malformed stable claims or a non-canonical value.
pub fn endpoint_revocation_execution_cancellation_id(
    value: &EndpointRevocationExecutionCancellationV1,
) -> Result<String, ContractError> {
    let stable = Stable {
        schema: &value.schema,
        cancellation_request_sha256: &value.cancellation_request_sha256,
        cancel_envelope_digest_sha256: &value.cancel_envelope_digest_sha256,
        pre_final_acceptance_request_sha256: &value.pre_final_acceptance_request_sha256,
        prepared_operation_digest_sha256: &value.prepared_operation_digest_sha256,
        opaque_owner_ref: &value.opaque_owner_ref,
        service_id: &value.service_id,
        pairwise_subject: &value.pairwise_subject,
        source_device_ref: &value.source_device_ref,
        source_session_ref: &value.source_session_ref,
        target_digest_sha256: &value.target_digest_sha256,
        begin_exchange_digest_sha256: &value.begin_exchange_digest_sha256,
        begin_command_digest_sha256: &value.begin_command_digest_sha256,
        finalize_command_id: &value.finalize_command_id,
        cancelled_state_revision: value.cancelled_state_revision,
        execution_reservation_id: &value.execution_reservation_id,
        cancellation_config_generation: value.cancellation_config_generation,
        cancellation_accepted_revision: value.cancellation_accepted_revision,
        operation: &value.operation,
        cancel_pending_request: &value.cancel_pending_request,
        issuer: &value.issuer,
        audience: &value.audience,
    };
    digest(CANCELLATION_DOMAIN, &stable)
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ContractError> {
    let json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(domain, &json)?,
    )))
}

#[derive(Serialize)]
struct Stable<'a> {
    schema: &'a str,
    cancellation_request_sha256: &'a str,
    cancel_envelope_digest_sha256: &'a str,
    pre_final_acceptance_request_sha256: &'a str,
    prepared_operation_digest_sha256: &'a str,
    opaque_owner_ref: &'a str,
    service_id: &'a str,
    pairwise_subject: &'a str,
    source_device_ref: &'a str,
    source_session_ref: &'a str,
    target_digest_sha256: &'a str,
    begin_exchange_digest_sha256: &'a str,
    begin_command_digest_sha256: &'a str,
    finalize_command_id: &'a str,
    cancelled_state_revision: u64,
    execution_reservation_id: &'a Option<String>,
    cancellation_config_generation: u64,
    cancellation_accepted_revision: u64,
    operation: &'a crate::ManagementOperationV2,
    cancel_pending_request: &'a ihat_identity_assertion_contracts::AuthorityRequestV1,
    issuer: &'a str,
    audience: &'a str,
}
