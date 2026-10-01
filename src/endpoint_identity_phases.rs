use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementCommandV2,
    RevocationIndependentCeremonyV1, RevocationSourceCeremonyV1, SignedAuthorityExchangeV1,
    SignedTargetDeviceProofV2,
};

pub(crate) fn source_approve(
    identity_exchange: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    finish_uv_exchange: &SignedAuthorityExchangeV1,
    ceremony: Option<&RevocationSourceCeremonyV1>,
    command: &ManagementCommandV2,
) -> Result<(), ContractError> {
    let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
    let fresh_uv =
        crate::endpoint_finish_uv::fresh_uv_from_finish_exchange(finish_uv_exchange, command)?;
    crate::endpoint_identity_context::selected_source(identity, prepared)?;
    crate::endpoint_identity_operation::fresh(identity, prepared, fresh_uv, command)?;
    crate::endpoint_revocation_binding::source(identity, prepared, fresh_uv, ceremony)
}

pub(crate) fn target_approve(
    identity_exchange: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    finish_uv_exchange: &SignedAuthorityExchangeV1,
    target_proof: &SignedTargetDeviceProofV2,
    command: &ManagementCommandV2,
) -> Result<(), ContractError> {
    let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
    let fresh_uv =
        crate::endpoint_finish_uv::fresh_uv_from_finish_exchange(finish_uv_exchange, command)?;
    crate::endpoint_identity_context::identity_pair(identity)?;
    crate::endpoint_identity_context::operation(identity, prepared)?;
    crate::endpoint_identity_operation::fresh(identity, prepared, fresh_uv, command)?;
    crate::endpoint_target_binding::context(identity, prepared, target_proof)?;
    crate::endpoint_target_binding::freshness(identity, prepared, fresh_uv, target_proof)
}

pub(crate) fn independent_approve(
    identity_exchange: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    finish_uv_exchange: &SignedAuthorityExchangeV1,
    ceremony: &RevocationIndependentCeremonyV1,
    command: &ManagementCommandV2,
) -> Result<(), ContractError> {
    let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
    let fresh_uv =
        crate::endpoint_finish_uv::fresh_uv_from_finish_exchange(finish_uv_exchange, command)?;
    crate::endpoint_identity_context::identity_pair(identity)?;
    crate::endpoint_identity_context::operation(identity, prepared)?;
    crate::endpoint_identity_operation::fresh(identity, prepared, fresh_uv, command)?;
    crate::endpoint_revocation_binding::independent(identity, prepared, ceremony)
}
