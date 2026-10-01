use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementOperationV2, SignedAuthorityExchangeV1,
};

pub const ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-prepared-lookup-request/v1";
pub const ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-prepared-lookup-response/v3";
const REQUEST_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-PREPARED-LOOKUP-REQUEST-V1\0";
const RESPONSE_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-PREPARED-LOOKUP-RESPONSE-V3\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPreparedLookupPhaseV1 {
    Target,
    Approval,
    Cancel,
    Reconcile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPreparedLookupRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub expected_state_revision: u64,
    pub phase: EndpointPreparedLookupPhaseV1,
    pub identity_exchange: SignedAuthorityExchangeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPreparedLookupResponseV1 {
    pub schema: String,
    pub request_id: String,
    pub request_digest_sha256: String,
    pub actor_device_ref: String,
    pub actor_session_ref: String,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub operation: ManagementOperationV2,
    pub prepared: EndpointPreparedOperationV2,
    #[serde(deserialize_with = "crate::endpoint_prepared_lookup_required::deserialize")]
    pub revocation_begin_exchange: Option<SignedAuthorityExchangeV1>,
    #[serde(deserialize_with = "crate::endpoint_prepared_lookup_required::deserialize")]
    pub pre_final_acceptance_request_sha256: Option<String>,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub key_id: String,
    pub signature: String,
}

/// Strictly decodes a bounded endpoint-internal lookup request.
///
/// # Errors
/// Rejects oversized, malformed, open, or invalid request documents.
pub fn decode_endpoint_prepared_lookup_request_strict(
    wire: &[u8],
) -> Result<EndpointPreparedLookupRequestV1, ContractError> {
    crate::endpoint_prepared_lookup_decode::decode(wire).and_then(|value| {
        validate_endpoint_prepared_lookup_request(&value)?;
        Ok(value)
    })
}

/// Strictly decodes a bounded signed lookup response.
///
/// # Errors
/// Rejects oversized, malformed, open, or invalid response documents.
pub fn decode_endpoint_prepared_lookup_response_strict(
    wire: &[u8],
) -> Result<EndpointPreparedLookupResponseV1, ContractError> {
    crate::endpoint_prepared_lookup_decode::decode(wire).and_then(|value| {
        validate_response_shape(&value)?;
        Ok(value)
    })
}

/// Returns the domain-separated JCS request digest.
///
/// # Errors
/// Rejects requests that cannot be canonically represented.
pub fn endpoint_prepared_lookup_request_digest(
    value: &EndpointPreparedLookupRequestV1,
) -> Result<String, ContractError> {
    let json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(REQUEST_DOMAIN, &json)?,
    )))
}

/// Returns canonical signed response bytes without its signature field.
///
/// # Errors
/// Rejects responses that cannot be canonically represented.
pub fn canonical_endpoint_prepared_lookup_response(
    value: &EndpointPreparedLookupResponseV1,
) -> Result<Vec<u8>, ContractError> {
    let mut json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    json.as_object_mut()
        .ok_or(ContractError::Invalid)?
        .remove("signature");
    crate::management_crypto::domain_jcs(RESPONSE_DOMAIN, &json)
}

/// Validates the closed request shape before central state access.
///
/// # Errors
/// Rejects invalid schemas, identifiers, revisions, or identity pairs.
pub fn validate_endpoint_prepared_lookup_request(
    value: &EndpointPreparedLookupRequestV1,
) -> Result<(), ContractError> {
    let valid = value.schema == ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA
        && crate::management_operation_validation::id(&value.request_id, 128)
        && crate::management_operation_validation::digest(&value.operation_id)
        && value.expected_state_revision > 0
        && crate::identity_evidence_from_exchange(&value.identity_exchange).is_ok();
    valid.then_some(()).ok_or(ContractError::Invalid)
}

pub(crate) fn validate_response_shape(
    value: &EndpointPreparedLookupResponseV1,
) -> Result<(), ContractError> {
    let valid = value.schema == ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA
        && crate::management_operation_validation::id(&value.request_id, 128)
        && crate::management_operation_validation::digest(&value.request_digest_sha256)
        && crate::management_operation_validation::reference(&value.actor_device_ref)
        && crate::management_operation_validation::reference(&value.actor_session_ref)
        && value.subject_revocation_epoch > 0
        && value.service_revocation_epoch > 0
        && value.device_revocation_epoch > 0
        && value.session_revocation_epoch > 0
        && value.issued_at_epoch_s < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 30
        && crate::management_operation_validation::id(&value.key_id, 128)
        && crate::management_operation_validation::lower_hex(&value.signature, 64)
        && crate::management_operation_validation::operation_valid(&value.operation)
        && crate::endpoint_envelope_validation::validate_prepared_shape(&value.prepared).is_ok();
    valid.then_some(()).ok_or(ContractError::Invalid)
}
