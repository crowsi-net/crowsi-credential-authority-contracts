use ihat_identity_assertion_contracts::SignedEvidenceV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementRequestV2, SignedAuthorityExchangeV1,
};

pub const ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-finalize-request/v2";
const REQUEST_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-REVOCATION-FINALIZE-REQUEST-V2\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationFinalizeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub expected_state_revision: u64,
    pub pre_final_state_revision: u64,
    pub reconcile_digest: String,
    pub source_approve_request: ManagementRequestV2,
    pub prepared: EndpointPreparedOperationV2,
    pub pre_final_request_sha256: String,
    pub accepted_identity_exchange: SignedAuthorityExchangeV1,
    pub execution_reservation_id: String,
    pub execution_reservation_token: SignedEvidenceV1,
    pub final_revoke_exchange: SignedAuthorityExchangeV1,
}

/// Strictly decodes the closed endpoint-to-central revocation finalization request.
///
/// # Errors
/// Rejects oversized, malformed, open, cross-operation, or wrong-final-command documents.
pub fn decode_endpoint_revocation_finalize_request_strict(
    wire: &[u8],
) -> Result<EndpointRevocationFinalizeRequestV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value: EndpointRevocationFinalizeRequestV1 =
        serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    validate_endpoint_revocation_finalize_request(&value)?;
    Ok(value)
}

/// Validates request shape and the final exchange against immutable prepared context.
///
/// This does not establish the stored Begin correlation or verify a response signature.
/// Central must additionally call `validate_endpoint_revocation_finalize_against_begin` and
/// verify the response with the authority trust pinned by pre-final acceptance.
///
/// # Errors
/// Rejects malformed identifiers, prepared state, or substituted final commands/results.
pub fn validate_endpoint_revocation_finalize_request(
    value: &EndpointRevocationFinalizeRequestV1,
) -> Result<(), ContractError> {
    crate::endpoint_revocation_finalize_validation::validate(value)
}

/// Correlates the final exchange with the exact Begin exchange accepted before side effects.
///
/// # Errors
/// Rejects a substituted Begin, target digest, response trust, or final result.
pub fn validate_endpoint_revocation_finalize_against_begin(
    value: &EndpointRevocationFinalizeRequestV1,
    stored_begin: &SignedAuthorityExchangeV1,
) -> Result<(), ContractError> {
    validate_endpoint_revocation_finalize_request(value)?;
    let begun = crate::endpoint_revocation_begin::validate(&value.prepared, stored_begin, None)?;
    if value.final_revoke_exchange.response.key_id != stored_begin.response.key_id
        || value.final_revoke_exchange.response.config_generation
            < stored_begin.response.config_generation
    {
        return Err(ContractError::Invalid);
    }
    let target =
        crate::endpoint_revocation_final::shape(&value.prepared, &value.final_revoke_exchange)?;
    (target == begun.target_digest)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

/// Correlates one signed final result with the exact accepted Begin and prepared operation.
///
/// # Errors
/// Rejects command, target, epoch, result, ceremony, response-key, or generation substitution.
pub fn validate_revocation_final_exchange_against_begin(
    prepared: &EndpointPreparedOperationV2,
    stored_begin: &SignedAuthorityExchangeV1,
    final_exchange: &SignedAuthorityExchangeV1,
) -> Result<(), ContractError> {
    let begun = crate::endpoint_revocation_begin::validate(prepared, stored_begin, None)?;
    if final_exchange.response.key_id != stored_begin.response.key_id
        || final_exchange.response.config_generation < stored_begin.response.config_generation
    {
        return Err(ContractError::Invalid);
    }
    let target = crate::endpoint_revocation_final::shape(prepared, final_exchange)?;
    (target == begun.target_digest)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

/// Returns the domain-separated JCS request digest used by transport and signed projections.
///
/// # Errors
/// Rejects a request that cannot be canonically represented.
pub fn endpoint_revocation_finalize_request_digest(
    value: &EndpointRevocationFinalizeRequestV1,
) -> Result<String, ContractError> {
    validate_endpoint_revocation_finalize_request(value)?;
    let json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(REQUEST_DOMAIN, &json)?,
    )))
}
