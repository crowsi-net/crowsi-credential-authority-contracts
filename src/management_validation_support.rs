use crate::{ContractError, management_operation_validation::id};
use serde::Serialize;
use std::collections::BTreeSet;

pub(crate) fn references(values: &[String], maximum: usize) -> bool {
    !values.is_empty() && references_allow_empty(values, maximum)
}
pub(crate) fn references_allow_empty(values: &[String], maximum: usize) -> bool {
    values.len() <= maximum
        && values
            .iter()
            .all(|v| super::management_operation_validation::reference(v))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
pub(crate) fn rfc3339(value: &str) -> bool {
    id(value, 64) && value.ends_with('Z') && value.contains('T')
}
pub(crate) fn bounded<T: Serialize>(value: &T) -> Result<(), ContractError> {
    let value = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    walk(&value)
}
fn walk(value: &serde_json::Value) -> Result<(), ContractError> {
    match value {
        serde_json::Value::String(v) if v.len() > 16_384 || v.chars().any(char::is_control) => {
            invalid()
        }
        serde_json::Value::Array(v) if v.len() > 1000 => invalid(),
        serde_json::Value::Array(v) => v.iter().try_for_each(walk),
        serde_json::Value::Object(v) => v.values().try_for_each(walk),
        _ => Ok(()),
    }
}
pub(crate) fn invalid<T>() -> Result<T, ContractError> {
    Err(ContractError::Invalid)
}
