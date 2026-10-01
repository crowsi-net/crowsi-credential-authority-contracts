use crate::{ContractError, EndpointPreparedLookupRequestV1, EndpointPreparedLookupResponseV1};

/// Verifies an exact fresh authority-signed prepared-operation lookup response.
///
/// # Errors
/// Rejects malformed, stale, substituted, wrongly signed, or phase-ineligible responses.
pub fn verify_endpoint_prepared_lookup_response_at(
    value: &EndpointPreparedLookupResponseV1,
    request: &EndpointPreparedLookupRequestV1,
    expected_key_id: &str,
    public_key_hex: &str,
    now: u64,
) -> Result<(), ContractError> {
    validate(value, request, now)?;
    if value.key_id != expected_key_id {
        return Err(ContractError::Invalid);
    }
    crate::management_crypto::verify(
        public_key_hex,
        &value.signature,
        &crate::canonical_endpoint_prepared_lookup_response(value)?,
    )
}

fn validate(
    value: &EndpointPreparedLookupResponseV1,
    request: &EndpointPreparedLookupRequestV1,
    now: u64,
) -> Result<(), ContractError> {
    crate::validate_endpoint_prepared_lookup_request(request)?;
    crate::endpoint_prepared_lookup::validate_response_shape(value)?;
    let identity = &crate::identity_evidence_from_exchange(&request.identity_exchange)?.assertion;
    let epochs = &identity.revocation_epochs;
    let exact = value.schema == crate::ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA
        && value.request_id == request.request_id
        && value.request_digest_sha256 == crate::endpoint_prepared_lookup_request_digest(request)?
        && value.actor_device_ref == identity.device_id
        && value.actor_session_ref == identity.session_ref
        && (
            value.subject_revocation_epoch,
            value.service_revocation_epoch,
            value.device_revocation_epoch,
            value.session_revocation_epoch,
        ) == (
            epochs.subject,
            epochs.service,
            epochs.device,
            epochs.session,
        )
        && value.operation.operation_id == request.operation_id
        && value.operation.state_revision == request.expected_state_revision
        && value.prepared.operation_id == request.operation_id
        && crate::endpoint_operation_id(&value.prepared)
            .is_ok_and(|id| id == value.prepared.operation_id)
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 30
        && (matches!(
            request.phase,
            crate::EndpointPreparedLookupPhaseV1::Cancel
                | crate::EndpointPreparedLookupPhaseV1::Reconcile
        ) || now < value.prepared.expires_at_epoch_s)
        && crate::endpoint_prepared_lookup_binding::identity_matches(request, value)
        && crate::endpoint_prepared_lookup_binding::operation_matches(value)
        && crate::endpoint_prepared_lookup_binding::phase(request, value)
        && crate::endpoint_prepared_lookup_revocation::exact(value, request.phase, now);
    exact.then_some(()).ok_or(ContractError::Invalid)
}
