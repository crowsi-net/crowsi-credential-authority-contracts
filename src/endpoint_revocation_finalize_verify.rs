use crate::{
    ContractError, EndpointRevocationFinalizeRequestV1, ManagementOperationState,
    ManagementProjectionBodyV2, ManagementProjectionV2,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationFinalizeProjectionTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

/// Verifies the fresh signed projection returned by the internal revocation-finalize route.
///
/// # Errors
/// Rejects cross-request, cross-owner, cross-peer, stale, malformed, or invalidly signed output.
pub fn verify_endpoint_revocation_finalize_projection_at(
    value: &ManagementProjectionV2,
    request: &EndpointRevocationFinalizeRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationFinalizeProjectionTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::validate_endpoint_revocation_finalize_request(request)?;
    crate::management_validation::projection(value)?;
    let ManagementProjectionBodyV2::Operation { operation } = &value.body else {
        return Err(ContractError::Invalid);
    };
    let identity = crate::identity_evidence_from_exchange(&request.accepted_identity_exchange)?;
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let expected_unknown_revision = request
        .expected_state_revision
        .checked_add(1)
        .ok_or(ContractError::Invalid)?;
    let expected_completed_revision = request
        .expected_state_revision
        .checked_add(2)
        .ok_or(ContractError::Invalid)?;
    let valid = value.request_id == request.source_approve_request.request_id
        && value.command_digest_sha256
            == crate::management_command_digest(&request.source_approve_request)?
        && value.issuer == trust.issuer
        && value.audience == trust.audience
        && value.service_id == intent_service(&request.prepared.intent)
        && value.pairwise_subject == request.prepared.pairwise_subject
        && value.opaque_account_ref == request.prepared.opaque_owner_ref
        && value.current_device_ref == request.prepared.source_device_ref
        && value.current_device_ref == expected_peer_device_ref
        && value.current_session_ref == request.prepared.source_session_ref
        && value.current_device_ref == assertion.device_id
        && value.current_session_ref == assertion.session_ref
        && value.service_id == assertion.service_id
        && value.pairwise_subject == assertion.pairwise_subject
        && value.subject_revocation_epoch == epochs.subject
        && value.service_revocation_epoch == epochs.service
        && value.device_revocation_epoch == epochs.device
        && value.session_revocation_epoch == epochs.session
        && value.device_posture_state == assertion.device_posture.state
        && value.device_posture_revision == assertion.device_posture.revision
        && value.device_proof_key_ref == assertion.device_proof_key_ref
        && value.snapshot_revision >= trust.minimum_snapshot_revision
        && value.key_id == trust.key_id
        && value.issued_at_epoch_s <= trust.now_epoch_s
        && trust.now_epoch_s < value.expires_at_epoch_s
        && operation.operation_id == request.operation_id
        && (matches!(operation.state, ManagementOperationState::Unknown)
            && operation.state_revision >= expected_unknown_revision
            && operation.reconcile_digest.as_deref() == Some(&request.reconcile_digest)
            || matches!(operation.state, ManagementOperationState::Completed)
                && operation.state_revision >= expected_completed_revision)
        && crate::endpoint_prepared_lookup_binding::operation_prepared(
            operation,
            &request.prepared,
        );
    if !valid {
        return Err(ContractError::Invalid);
    }
    crate::management_crypto::verify(
        trust.public_key_hex,
        &value.signature,
        &crate::canonical_management_projection(value)?,
    )
}

fn intent_service(value: &crate::ManagementIntentV2) -> &str {
    match value {
        crate::ManagementIntentV2::DeviceTransfer { service_id, .. }
        | crate::ManagementIntentV2::DeviceRevocation { service_id, .. }
        | crate::ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    }
}
