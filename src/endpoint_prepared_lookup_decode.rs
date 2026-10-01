use serde::Deserialize;

use crate::ContractError;

pub(crate) fn decode<T: for<'de> Deserialize<'de>>(wire: &[u8]) -> Result<T, ContractError> {
    if wire.is_empty() || wire.len() > crate::MAX_MANAGEMENT_WIRE_BYTES {
        return Err(ContractError::Invalid);
    }
    let mut decoder = serde_json::Deserializer::from_slice(wire);
    let value = T::deserialize(&mut decoder).map_err(|_| ContractError::Invalid)?;
    decoder.end().map_err(|_| ContractError::Invalid)?;
    Ok(value)
}
