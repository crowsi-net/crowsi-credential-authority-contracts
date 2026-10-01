use crate::{
    ContractError, MAX_MANAGEMENT_WIRE_BYTES, ManagementProjectionV2, ManagementRequestV2,
    management_validation,
};

/// Decodes one bounded, closed browser-to-endpoint management request.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, trailing, unknown-field, or invalid input.
pub fn decode_management_request_strict(
    bytes: &[u8],
) -> Result<ManagementRequestV2, ContractError> {
    let value = decode(bytes)?;
    crate::management_request_validation::request(&value)?;
    Ok(value)
}

/// Decodes one bounded, closed authority-signed management projection.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, trailing, unknown-field, or invalid input.
pub fn decode_management_projection_strict(
    bytes: &[u8],
) -> Result<ManagementProjectionV2, ContractError> {
    let value = decode(bytes)?;
    management_validation::projection(&value)?;
    Ok(value)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ContractError> {
    if bytes.is_empty() || bytes.len() > MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    serde_json::from_slice(bytes).map_err(|_| ContractError::Invalid)
}
