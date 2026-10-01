pub(crate) fn independent(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    value: &crate::RevocationIndependentCeremonyV1,
) -> Result<(), ContractError> {
    let pre_final = crate::RevocationIndependentPreFinalCeremonyV1 {
        begin: value.begin.clone(),
        approval: value.approval.clone(),
    };
    let begun = independent_pre_final(identity, prepared, &pre_final)?;
    crate::endpoint_revocation_chain::validate(value, begun)?;
    crate::endpoint_revocation_final::validate(prepared, begun, &value.final_revoke)
}

pub(crate) fn independent_pre_final<'a>(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    value: &'a crate::RevocationIndependentPreFinalCeremonyV1,
) -> Result<&'a ihat_identity_assertion_contracts::RevocationCeremonyMetadata, ContractError> {
    let begun = crate::endpoint_revocation_begin::validate(prepared, &value.begin, None)?;
    crate::endpoint_revocation_chain::partial(value, begun)?;
    let requirements = requirements(prepared)?;
    let actor = &identity.assertion.device_id;
    if !begun.independent_approval_required
        || actor == &prepared.source_device_ref
        || actor == &requirements.target_device_ref
    {
        return Err(ContractError::Invalid);
    }
    crate::endpoint_revocation_approval::validate(
        identity,
        prepared,
        requirements,
        begun,
        &value.approval,
    )?;
    Ok(begun)
}
