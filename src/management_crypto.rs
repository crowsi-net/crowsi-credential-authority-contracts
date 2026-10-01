use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ContractError, MANAGEMENT_COMMAND_DOMAIN, MANAGEMENT_PROJECTION_DOMAIN, ManagementProjectionV2,
    ManagementRequestV2,
};

/// Returns the domain-separated RFC 8785/JCS SHA-256 binding for one exact request.
///
/// # Errors
///
/// Rejects a request that cannot be represented as canonical JSON.
pub fn management_command_digest(value: &ManagementRequestV2) -> Result<String, ContractError> {
    let value = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    let mut payload = Vec::from(MANAGEMENT_COMMAND_DOMAIN);
    write_jcs(&value, &mut payload)?;
    Ok(hex::encode(Sha256::digest(payload)))
}

/// Produces domain-separated RFC 8785/JCS bytes without the signature field.
///
/// # Errors
///
/// Rejects a projection that cannot be represented as a closed JSON object.
pub fn canonical_management_projection(
    value: &ManagementProjectionV2,
) -> Result<Vec<u8>, ContractError> {
    let mut value = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    value
        .as_object_mut()
        .ok_or(ContractError::Invalid)?
        .remove("signature");
    let mut output = Vec::from(MANAGEMENT_PROJECTION_DOMAIN);
    write_jcs(&value, &mut output)?;
    Ok(output)
}

pub(crate) fn verify(public: &str, signature: &str, payload: &[u8]) -> Result<(), ContractError> {
    let key: [u8; 32] = lower_hex(public, 32)?
        .try_into()
        .map_err(|_| ContractError::Invalid)?;
    let signature: [u8; 64] = lower_hex(signature, 64)?
        .try_into()
        .map_err(|_| ContractError::Invalid)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| ContractError::Invalid)?;
    key.verify_strict(payload, &Signature::from_bytes(&signature))
        .map_err(|_| ContractError::Invalid)
}

fn lower_hex(value: &str, length: usize) -> Result<Vec<u8>, ContractError> {
    if value.len() != length * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(ContractError::Invalid);
    }
    hex::decode(value).map_err(|_| ContractError::Invalid)
}

fn write_jcs(value: &Value, output: &mut Vec<u8>) -> Result<(), ContractError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(v) => output.extend_from_slice(if *v { b"true" } else { b"false" }),
        Value::Number(v) => output.extend_from_slice(v.to_string().as_bytes()),
        Value::String(v) => output.extend_from_slice(
            serde_json::to_string(v)
                .map_err(|_| ContractError::Invalid)?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_jcs(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|_| ContractError::Invalid)?
                        .as_bytes(),
                );
                output.push(b':');
                write_jcs(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(crate) fn domain_jcs(domain: &[u8], value: &Value) -> Result<Vec<u8>, ContractError> {
    let mut output = Vec::from(domain);
    write_jcs(value, &mut output)?;
    Ok(output)
}
