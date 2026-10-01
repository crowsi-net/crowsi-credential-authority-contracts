use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointRevocationExecutionCancelRequestV1,
    EndpointRevocationExecutionCancellationV1, SignedAuthorityExchangeV1,
};

pub const ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-execution-cancel-finalize-request/v1";
const REQUEST_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-REVOCATION-EXECUTION-CANCEL-FINALIZE-REQUEST-V1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionCancelFinalizeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub cancellation_request: Box<EndpointRevocationExecutionCancelRequestV1>,
    pub cancellation: Box<EndpointRevocationExecutionCancellationV1>,
    pub cancel_pending_exchange: SignedAuthorityExchangeV1,
}

/// Strictly decodes one iHAT-cleanup acknowledgement request.
///
/// # Errors
/// Rejects empty, oversized, open, malformed, or cross-operation documents.
pub fn decode_endpoint_revocation_execution_cancel_finalize_request_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionCancelFinalizeRequestV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value = serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_cancel_finalize_validation::validate(&value)?;
    Ok(value)
}

/// Returns the domain-separated exact cleanup acknowledgement request digest.
///
/// # Errors
/// Rejects an invalid or non-canonical request.
pub fn endpoint_revocation_execution_cancel_finalize_request_digest(
    value: &EndpointRevocationExecutionCancelFinalizeRequestV1,
) -> Result<String, ContractError> {
    crate::endpoint_revocation_execution_cancel_finalize_validation::validate(value)?;
    let json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(REQUEST_DOMAIN, &json)?,
    )))
}
