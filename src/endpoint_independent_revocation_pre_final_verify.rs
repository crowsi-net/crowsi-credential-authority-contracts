use crate::{
    ContractError, EndpointIndependentRevocationPreFinalRequestV1, ManagementOperationState,
    ManagementProjectionBinding, ManagementProjectionBodyV2, ManagementProjectionV2,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIndependentRevocationPreFinalProjectionTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIndependentRevocationPreFinalProjectionHistoricTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_snapshot_revision: u64,
    pub accepted_at_epoch_s: u64,
}

/// Verifies a fresh central pre-final acceptance before an independent actor may reserve Final.
///
/// # Errors
/// Rejects cross-request, cross-peer, cross-owner, stale, malformed, or unsigned output.
pub fn verify_endpoint_independent_revocation_pre_final_projection_at(
    value: &ManagementProjectionV2,
    request: &EndpointIndependentRevocationPreFinalRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointIndependentRevocationPreFinalProjectionTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_independent_revocation_pre_final_validation::validate(request)?;
    let identity = crate::identity_evidence_from_exchange(&request.accepted_identity_exchange)?;
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let ManagementProjectionBodyV2::Operation { operation } = &value.body else {
        return Err(ContractError::Invalid);
    };
    let requirements = request
        .prepared
        .revocation
        .as_ref()
        .ok_or(ContractError::Invalid)?;
    let valid = assertion.device_id == expected_peer_device_ref
        && assertion.device_id != request.prepared.source_device_ref
        && assertion.device_id != requirements.target_device_ref
        && operation.operation_id == request.operation_id
        && operation.state == ManagementOperationState::AwaitingRevocationFinal
        && request.expected_state_revision.checked_add(1) == Some(operation.state_revision)
        && crate::endpoint_prepared_lookup_binding::operation_prepared(
            operation,
            &request.prepared,
        );
    if !valid {
        return Err(ContractError::Invalid);
    }
    let digest = crate::management_command_digest(&request.approve_revocation_request)?;
    crate::verify_management_projection_at(
        value,
        &ManagementProjectionBinding {
            request_id: &request.approve_revocation_request.request_id,
            command_digest_sha256: &digest,
            issuer: trust.issuer,
            audience: trust.audience,
            service_id: &assertion.service_id,
            pairwise_subject: &assertion.pairwise_subject,
            opaque_account_ref: &request.prepared.opaque_owner_ref,
            current_device_ref: expected_peer_device_ref,
            current_session_ref: &assertion.session_ref,
            subject_revocation_epoch: epochs.subject,
            service_revocation_epoch: epochs.service,
            device_revocation_epoch: epochs.device,
            session_revocation_epoch: epochs.session,
            device_posture_state: &assertion.device_posture.state,
            device_posture_revision: assertion.device_posture.revision,
            device_proof_key_ref: &assertion.device_proof_key_ref,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
        },
        trust.key_id,
        trust.public_key_hex,
        trust.now_epoch_s,
    )
}

/// Revalidates a durably accepted pre-final projection at its original acceptance time.
///
/// The caller must supply the exact management key pinned with the durable acceptance.
///
/// # Errors
/// Rejects a projection that was not live, exact, and correctly signed when accepted.
pub fn verify_endpoint_independent_revocation_pre_final_projection_historic(
    value: &ManagementProjectionV2,
    request: &EndpointIndependentRevocationPreFinalRequestV1,
    expected_peer_device_ref: &str,
    trust: &EndpointIndependentRevocationPreFinalProjectionHistoricTrustV1<'_>,
) -> Result<(), ContractError> {
    verify_endpoint_independent_revocation_pre_final_projection_at(
        value,
        request,
        expected_peer_device_ref,
        &EndpointIndependentRevocationPreFinalProjectionTrustV1 {
            issuer: trust.issuer,
            audience: trust.audience,
            key_id: trust.key_id,
            public_key_hex: trust.public_key_hex,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: trust.accepted_at_epoch_s,
        },
    )
}
