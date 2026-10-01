use ihat_identity_assertion_contracts::SignedEvidenceV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementRequestV2, SignedAuthorityExchangeV1,
};

pub const ENDPOINT_INDEPENDENT_REVOCATION_FINALIZE_REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-independent-revocation-finalize-request/v1";
const REQUEST_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-INDEPENDENT-REVOCATION-FINALIZE-REQUEST-V1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointIndependentRevocationFinalizeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub expected_state_revision: u64,
    pub pre_final_state_revision: u64,
    pub reconcile_digest: String,
    pub approve_revocation_request: ManagementRequestV2,
    pub prepared: EndpointPreparedOperationV2,
    pub pre_final_request_sha256: String,
    pub accepted_identity_exchange: SignedAuthorityExchangeV1,
    pub begin_exchange: SignedAuthorityExchangeV1,
    pub approval_exchange: SignedAuthorityExchangeV1,
    pub execution_reservation_id: String,
    pub execution_reservation_token: SignedEvidenceV1,
    pub final_revoke_exchange: SignedAuthorityExchangeV1,
}

/// Strictly decodes one closed independent revocation finalization request.
///
/// # Errors
/// Rejects oversized, malformed, open, cross-operation, or substituted documents.
pub fn decode_endpoint_independent_revocation_finalize_request_strict(
    wire: &[u8],
) -> Result<EndpointIndependentRevocationFinalizeRequestV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value: EndpointIndependentRevocationFinalizeRequestV1 =
        serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_independent_revocation_finalize_validation::validate(&value)?;
    Ok(value)
}

/// Returns the domain-separated exact independent-finalize request digest.
///
/// # Errors
/// Rejects an invalid or non-canonical request.
pub fn endpoint_independent_revocation_finalize_request_digest(
    value: &EndpointIndependentRevocationFinalizeRequestV1,
) -> Result<String, ContractError> {
    crate::endpoint_independent_revocation_finalize_validation::validate(value)?;
    let json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(REQUEST_DOMAIN, &json)?,
    )))
}
