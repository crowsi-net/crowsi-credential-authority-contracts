/// Strictly decodes one terminal Cancel-to-iHAT cleanup request.
///
/// # Errors
/// Rejects empty, oversized, open, malformed, or cross-operation documents.
pub fn decode_endpoint_revocation_execution_cancel_request_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionCancelRequestV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value = serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_cancel_validation::request(&value)?;
    Ok(value)
}

/// Strictly decodes one signed cancellation token wrapper.
///
/// # Errors
/// Rejects empty, oversized, open, malformed, or invalid documents.
pub fn decode_endpoint_revocation_execution_cancellation_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionCancellationV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value = serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_cancel_validation::cancellation(&value)?;
    Ok(value)
}
