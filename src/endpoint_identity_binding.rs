use crate::{ContractError, EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2};

use crate::endpoint_identity_context::{
    creation_source, current_source, identity_pair, operation as operation_identity,
};

pub(crate) fn validate(value: &EndpointManagementEnvelopeV2) -> Result<(), ContractError> {
    use EndpointManagementEvidenceV2::{
        ActorOptions, Cancel, IndependentApprove, Passive, Reconcile, SourceApprove, SourceOptions,
        TargetApprove,
    };
    match &value.evidence {
        Passive { identity_exchange } => {
            identity_pair(crate::identity_evidence_from_exchange(identity_exchange)?)
        }
        SourceOptions {
            identity_exchange,
            prepared,
            uv_options,
        } => {
            let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
            creation_source(identity, prepared)?;
            crate::endpoint_identity_operation::options(identity, prepared, uv_options)
        }
        ActorOptions {
            identity_exchange,
            prepared,
            uv_options,
        } => {
            let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
            identity_pair(identity)?;
            operation_identity(identity, prepared)?;
            crate::endpoint_actor_binding::options(
                identity,
                prepared,
                &value.browser_request.command,
            )?;
            crate::endpoint_identity_operation::options(identity, prepared, uv_options)
        }
        SourceApprove {
            identity_exchange,
            prepared,
            finish_uv_exchange,
            revocation_ceremony,
        } => crate::endpoint_identity_phases::source_approve(
            identity_exchange,
            prepared,
            finish_uv_exchange,
            revocation_ceremony.as_ref(),
            &value.browser_request.command,
        ),
        TargetApprove {
            identity_exchange,
            prepared,
            finish_uv_exchange,
            target_proof,
        } => crate::endpoint_identity_phases::target_approve(
            identity_exchange,
            prepared,
            finish_uv_exchange,
            target_proof,
            &value.browser_request.command,
        ),
        IndependentApprove {
            identity_exchange,
            prepared,
            finish_uv_exchange,
            revocation_ceremony,
        } => crate::endpoint_identity_phases::independent_approve(
            identity_exchange,
            prepared,
            finish_uv_exchange,
            revocation_ceremony,
            &value.browser_request.command,
        ),
        Cancel {
            identity_exchange,
            prepared,
        } => current_source(
            crate::identity_evidence_from_exchange(identity_exchange)?,
            prepared,
        ),
        Reconcile {
            identity_exchange,
            prepared,
        } => {
            let identity = crate::identity_evidence_from_exchange(identity_exchange)?;
            crate::endpoint_actor_binding::reconcile(identity, prepared)
        }
    }
}
