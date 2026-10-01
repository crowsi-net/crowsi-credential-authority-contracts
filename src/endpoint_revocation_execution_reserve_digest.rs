use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointRevocationExecutionReservationV1,
    EndpointRevocationExecutionReserveRequestV1,
};

const REQUEST_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-REVOCATION-EXECUTION-RESERVE-REQUEST-V1\0";
const RESERVATION_ID_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-REVOCATION-EXECUTION-RESERVATION-ID-V1\0";
const EXCHANGE_DOMAIN: &[u8] = b"CROWSI-ENDPOINT-SIGNED-AUTHORITY-EXCHANGE-V1\0";
pub(crate) const RESERVATION_RESPONSE_DOMAIN: &[u8] =
    b"CROWSI-ENDPOINT-REVOCATION-EXECUTION-RESERVATION-V1\0";

/// Returns the domain-separated exact reserve-request digest.
///
/// # Errors
/// Rejects an invalid or non-canonical request.
pub fn endpoint_revocation_execution_reserve_request_digest(
    value: &EndpointRevocationExecutionReserveRequestV1,
) -> Result<String, ContractError> {
    crate::endpoint_revocation_execution_reserve_validation::request(value)?;
    digest(REQUEST_DOMAIN, value)
}

/// Recomputes the immutable reservation identifier signed into the iHAT token.
///
/// # Errors
/// Rejects claims that cannot be represented canonically.
pub fn endpoint_revocation_execution_reservation_id(
    value: &EndpointRevocationExecutionReservationV1,
) -> Result<String, ContractError> {
    #[derive(Serialize)]
    struct Stable<'a> {
        reservation_request_sha256: &'a str,
        original_request_id: &'a str,
        original_command_digest_sha256: &'a str,
        prepared_operation_digest_sha256: &'a str,
        reconcile_digest: &'a str,
        opaque_owner_ref: &'a str,
        service_id: &'a str,
        pairwise_subject: &'a str,
        source_device_ref: &'a str,
        finalizer_device_ref: &'a str,
        target_digest_sha256: &'a str,
        begin_exchange_digest_sha256: &'a str,
        approval_exchange_digest_sha256: &'a Option<String>,
        final_command_digest_sha256: &'a str,
        pre_final_state_revision: u64,
        reserved_state_revision: u64,
        reservation_config_generation: u64,
        issuer: &'a str,
        audience: &'a str,
    }
    digest(
        RESERVATION_ID_DOMAIN,
        &Stable {
            reservation_request_sha256: &value.reservation_request_sha256,
            original_request_id: &value.original_request_id,
            original_command_digest_sha256: &value.original_command_digest_sha256,
            prepared_operation_digest_sha256: &value.prepared_operation_digest_sha256,
            reconcile_digest: &value.reconcile_digest,
            opaque_owner_ref: &value.opaque_owner_ref,
            service_id: &value.service_id,
            pairwise_subject: &value.pairwise_subject,
            source_device_ref: &value.source_device_ref,
            finalizer_device_ref: &value.finalizer_device_ref,
            target_digest_sha256: &value.target_digest_sha256,
            begin_exchange_digest_sha256: &value.begin_exchange_digest_sha256,
            approval_exchange_digest_sha256: &value.approval_exchange_digest_sha256,
            final_command_digest_sha256: &value.final_command_digest_sha256,
            pre_final_state_revision: value.pre_final_state_revision,
            reserved_state_revision: value.reserved_state_revision,
            reservation_config_generation: value.reservation_config_generation,
            issuer: &value.issuer,
            audience: &value.audience,
        },
    )
}

/// Returns the domain-separated digest of one exact signed authority exchange.
///
/// # Errors
/// Rejects an exchange that cannot be represented canonically.
pub fn endpoint_signed_authority_exchange_digest(
    value: &crate::SignedAuthorityExchangeV1,
) -> Result<String, ContractError> {
    digest(EXCHANGE_DOMAIN, value)
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ContractError> {
    let json = serde_json::to_value(value).map_err(|_| ContractError::Invalid)?;
    Ok(hex::encode(Sha256::digest(
        crate::management_crypto::domain_jcs(domain, &json)?,
    )))
}
