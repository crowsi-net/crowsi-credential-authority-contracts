use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementRequestV2,
    RevocationIndependentPreFinalCeremonyV1, SignedAuthorityExchangeV1,
};

pub const ENDPOINT_INDEPENDENT_REVOCATION_PRE_FINAL_REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-independent-revocation-pre-final-request/v1";
const REQUEST_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-INDEPENDENT-REVOCATION-PRE-FINAL-REQUEST-V1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointIndependentRevocationPreFinalRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub expected_state_revision: u64,
    pub approve_revocation_request: ManagementRequestV2,
    pub prepared: EndpointPreparedOperationV2,
    pub selected_identity_exchange: SignedAuthorityExchangeV1,
    pub begin_uv_exchange: SignedAuthorityExchangeV1,
    pub finish_uv_exchange: SignedAuthorityExchangeV1,
    pub accepted_identity_exchange: SignedAuthorityExchangeV1,
    pub revocation_ceremony: RevocationIndependentPreFinalCeremonyV1,
}

/// Strictly decodes one closed independent-revocation pre-final request.
///
/// # Errors
/// Rejects oversized, malformed, open, cross-operation, or cross-ceremony documents.
pub fn decode_endpoint_independent_revocation_pre_final_request_strict(
    wire: &[u8],
) -> Result<EndpointIndependentRevocationPreFinalRequestV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value: EndpointIndependentRevocationPreFinalRequestV1 =
        serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_independent_revocation_pre_final_validation::validate(&value)?;
    Ok(value)
}

/// Returns the domain-separated JCS digest for durable pre-final acceptance.
///
/// # Errors
/// Rejects an invalid or non-canonical request.
pub fn endpoint_independent_revocation_pre_final_request_digest(
    value: &EndpointIndependentRevocationPreFinalRequestV1,
) -> Result<String, ContractError> {
    crate::endpoint_independent_revocation_pre_final_validation::validate(value)?;
    let json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(REQUEST_DOMAIN, &json)?,
    )))
}
