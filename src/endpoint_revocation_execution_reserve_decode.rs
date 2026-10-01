/// Strictly decodes one closed execution-reservation request.
///
/// # Errors
/// Rejects oversized, malformed, open, or cross-operation documents.
pub fn decode_endpoint_revocation_execution_reserve_request_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionReserveRequestV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value: EndpointRevocationExecutionReserveRequestV1 =
        serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_reserve_validation::request(&value)?;
    Ok(value)
}

/// Strictly decodes one closed signed execution reservation.
///
/// # Errors
/// Rejects oversized, malformed, open, or internally inconsistent documents.
pub fn decode_endpoint_revocation_execution_reservation_strict(
    wire: &[u8],
) -> Result<EndpointRevocationExecutionReservationV1, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let value: EndpointRevocationExecutionReservationV1 =
        serde_json::from_slice(wire).map_err(|_| ContractError::Invalid)?;
    crate::endpoint_revocation_execution_reserve_validation::reservation(&value)?;
    Ok(value)
}
