use ihat_identity_assertion_contracts::RevocationCeremonyMetadata;

use crate::{
    ContractError, RevocationIndependentCeremonyV1, RevocationIndependentPreFinalCeremonyV1,
};

pub(crate) fn validate(
    value: &RevocationIndependentCeremonyV1,
    begun: &RevocationCeremonyMetadata,
) -> Result<(), ContractError> {
    partial(
        &RevocationIndependentPreFinalCeremonyV1 {
            begin: value.begin.clone(),
            approval: value.approval.clone(),
        },
        begun,
    )?;
    let responses = [
        &value.begin.response,
        &value.approval.response,
        &value.final_revoke.response,
    ];
    let generations = responses.map(|response| response.config_generation);
    let issued = responses.map(|response| response.issued_at_epoch_s);
    let exact = responses[1..]
        .iter()
        .all(|response| response.key_id == responses[0].key_id)
        && generations.windows(2).all(|pair| pair[0] <= pair[1])
        && issued.windows(2).all(|pair| pair[0] <= pair[1])
        && issued[2] < begun.expires_at_epoch_s;
    exact.then_some(()).ok_or(ContractError::Invalid)
}

pub(crate) fn partial(
    value: &RevocationIndependentPreFinalCeremonyV1,
    begun: &RevocationCeremonyMetadata,
) -> Result<(), ContractError> {
    let begin_response = &value.begin.response;
    let approval = &value.approval.response;
    let exact = approval.key_id == begin_response.key_id
        && approval.config_generation >= begin_response.config_generation
        && approval.issued_at_epoch_s >= begin_response.issued_at_epoch_s
        && approval.issued_at_epoch_s < begun.expires_at_epoch_s;
    exact.then_some(()).ok_or(ContractError::Invalid)
}
