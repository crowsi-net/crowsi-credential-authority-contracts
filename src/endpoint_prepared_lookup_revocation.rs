use ihat_identity_assertion_contracts::RevocationCeremonyStateDto;

use crate::{
    EndpointPreparedLookupPhaseV1 as Phase, EndpointPreparedLookupResponseV1,
    ManagementOperationState,
};

pub(crate) fn exact(
    value: &EndpointPreparedLookupResponseV1,
    phase: Phase,
    now_epoch_s: u64,
) -> bool {
    let begin = match phase {
        Phase::Approval => approval(value, now_epoch_s),
        Phase::Target | Phase::Cancel | Phase::Reconcile => {
            value.revocation_begin_exchange.is_none()
        }
    };
    begin && pre_final_digest(value, phase)
}

fn pre_final_digest(value: &EndpointPreparedLookupResponseV1, phase: Phase) -> bool {
    match (phase, value.operation.state) {
        (Phase::Cancel, ManagementOperationState::AwaitingRevocationFinal) => value
            .pre_final_acceptance_request_sha256
            .as_deref()
            .is_some_and(crate::management_operation_validation::digest),
        _ => value.pre_final_acceptance_request_sha256.is_none(),
    }
}

fn approval(value: &EndpointPreparedLookupResponseV1, now_epoch_s: u64) -> bool {
    let Some(exchange) = value.revocation_begin_exchange.as_ref() else {
        return false;
    };
    let Ok(begun) = crate::endpoint_revocation_begin::validate(&value.prepared, exchange, None)
    else {
        return false;
    };
    value.operation.state == ManagementOperationState::AwaitingIndependentApproval
        && begun.finalize_command_id == value.prepared.operation_id
        && begun.independent_approval_required
        && begun.state == RevocationCeremonyStateDto::AwaitingIndependentApproval
        && exchange.response.issued_at_epoch_s <= now_epoch_s
        && now_epoch_s < begun.expires_at_epoch_s
        && value.expires_at_epoch_s <= begun.expires_at_epoch_s
}
