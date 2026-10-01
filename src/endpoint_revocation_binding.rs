use ihat_identity_assertion_contracts::{
    AuthorityResult, FreshUvV1, IdentityEvidenceMetadata, ResponseOutcome,
};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EndpointManagementEvidenceV2, EndpointPreparedOperationV2, ManagementIntentV2,
    RevocationRequirementsV2, RevocationSourceCeremonyV1, endpoint_operation_digest,
};

const COMMAND_ID_DOMAIN: &[u8] = b"CROWSI-REVOCATION-COMMAND-ID-V2\0";

pub(crate) fn source(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    ceremony: Option<&RevocationSourceCeremonyV1>,
) -> Result<(), ContractError> {
    if matches!(prepared.intent, ManagementIntentV2::DeviceTransfer { .. }) {
        return if ceremony.is_none() && prepared.revocation.is_none() {
            Ok(())
        } else {
            Err(ContractError::Invalid)
        };
    }
    let ceremony = ceremony.ok_or(ContractError::Invalid)?;
    crate::endpoint_revocation_begin::validate(prepared, &ceremony.begin, Some(fresh))?;
    if ceremony.final_revoke.is_some() {
        return Err(ContractError::Invalid);
    }
    let source_exact = identity.assertion.device_id == prepared.source_device_ref;
    source_exact.then_some(()).ok_or(ContractError::Invalid)
}

pub(crate) fn requirements(
    value: &EndpointPreparedOperationV2,
) -> Result<&RevocationRequirementsV2, ContractError> {
    crate::endpoint_revocation_requirements::validate(value)
}

/// Derives the one allowed begin command identifier from the immutable intent.
///
/// # Errors
/// Rejects an operation that cannot be canonically encoded.
pub fn revocation_begin_command_id(
    value: &EndpointPreparedOperationV2,
) -> Result<String, ContractError> {
    phase_command_id(value, "begin", &value.source_device_ref)
}

/// Derives the one allowed approval command identifier for an independent actor.
///
/// # Errors
/// Rejects an operation or actor that cannot be canonically encoded.
pub fn revocation_approval_command_id(
    value: &EndpointPreparedOperationV2,
    actor_device_ref: &str,
) -> Result<String, ContractError> {
    phase_command_id(value, "approval", actor_device_ref)
}

fn phase_command_id(
    value: &EndpointPreparedOperationV2,
    phase: &str,
    actor: &str,
) -> Result<String, ContractError> {
    let operation = endpoint_operation_digest(value)?;
    let mut digest = Sha256::new();
    digest.update(COMMAND_ID_DOMAIN);
    for field in [&operation, phase, actor] {
        digest.update(
            u32::try_from(field.len())
                .map_err(|_| ContractError::Invalid)?
                .to_be_bytes(),
        );
        digest.update(field.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

/// Rejects a durable revocation ceremony at or after its signed expiry.
///
/// # Errors
/// Rejects a malformed, non-committed, or expired ceremony.
pub fn validate_revocation_ceremony_at(
    value: &EndpointManagementEvidenceV2,
    now_epoch_s: u64,
) -> Result<(), ContractError> {
    let exchange = match value {
        EndpointManagementEvidenceV2::SourceApprove {
            revocation_ceremony: Some(value),
            ..
        } => Some(&value.begin),
        EndpointManagementEvidenceV2::IndependentApprove {
            revocation_ceremony,
            ..
        } => Some(&revocation_ceremony.begin),
        _ => None,
    };
    let Some(exchange) = exchange else {
        return Ok(());
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(value),
    } = &exchange.response.outcome
    else {
        return Err(ContractError::Invalid);
    };
    (now_epoch_s < value.expires_at_epoch_s)
        .then_some(())
        .ok_or(ContractError::Invalid)
}

include!("endpoint_revocation_binding_independent.rs");
