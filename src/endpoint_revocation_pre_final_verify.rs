use crate::{
    ContractError, EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionBinding, ManagementProjectionBodyV2,
    ManagementProjectionV2,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRevocationPreFinalProjectionTrustV1<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub public_key_hex: &'a str,
    pub minimum_snapshot_revision: u64,
    pub now_epoch_s: u64,
}

/// Verifies a fresh pre-final acceptance for an exact, possibly historic `SourceApprove` envelope.
///
/// The authority projection is the trust root for historic identity and Begin evidence. Callers
/// must not invoke the irreversible Final command until this verification succeeds.
///
/// # Errors
/// Rejects non-self revocation, cross-request, cross-peer, stale, malformed, or unsigned output.
pub fn verify_endpoint_revocation_pre_final_projection_at(
    value: &ManagementProjectionV2,
    envelope: &EndpointManagementEnvelopeV2,
    expected_peer_device_ref: &str,
    trust: &EndpointRevocationPreFinalProjectionTrustV1<'_>,
) -> Result<(), ContractError> {
    crate::endpoint_envelope_validation::validate(envelope)?;
    let (
        ManagementCommandV2::SourceApprove {
            operation_id,
            expected_state_revision,
            ..
        },
        EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange,
            prepared,
            revocation_ceremony: Some(ceremony),
            ..
        },
    ) = (&envelope.browser_request.command, &envelope.evidence)
    else {
        return Err(ContractError::Invalid);
    };
    let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let self_revocation = prepared
        .revocation
        .as_ref()
        .is_some_and(|item| item.target_device_ref == prepared.source_device_ref)
        && ceremony.final_revoke.is_none();
    let begin_live = matches!(
        &ceremony.begin.response.outcome,
        ihat_identity_assertion_contracts::ResponseOutcome::Committed {
            result: ihat_identity_assertion_contracts::AuthorityResult::RevocationBegun(result),
        } if trust.now_epoch_s < result.expires_at_epoch_s
    );
    let ManagementProjectionBodyV2::Operation { operation } = &value.body else {
        return Err(ContractError::Invalid);
    };
    let valid = self_revocation
        && begin_live
        && operation_id == &prepared.operation_id
        && expected_peer_device_ref == prepared.source_device_ref
        && operation.operation_id == *operation_id
        && operation.state == ManagementOperationState::AwaitingRevocationFinal
        && expected_state_revision.checked_add(1) == Some(operation.state_revision)
        && crate::endpoint_prepared_lookup_binding::operation_prepared(operation, prepared);
    if !valid {
        return Err(ContractError::Invalid);
    }
    let digest = crate::management_command_digest(&envelope.browser_request)?;
    crate::verify_management_projection_at(
        value,
        &ManagementProjectionBinding {
            request_id: &envelope.browser_request.request_id,
            command_digest_sha256: &digest,
            issuer: trust.issuer,
            audience: trust.audience,
            service_id: &assertion.service_id,
            pairwise_subject: &assertion.pairwise_subject,
            opaque_account_ref: &prepared.opaque_owner_ref,
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
