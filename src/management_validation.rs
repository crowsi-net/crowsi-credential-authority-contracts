use crate::management_operation_validation::{id, lower_hex, operation_valid, reference};
use crate::management_validation_support::{bounded, invalid, references_allow_empty, rfc3339};
use crate::{
    ContractError, MANAGEMENT_PROJECTION_MAX_TTL_SECONDS, MANAGEMENT_PROJECTION_SCHEMA,
    ManagementCredentialV2, ManagementDeviceV2, ManagementProjectionBodyV2, ManagementProjectionV2,
    ManagementSessionV2, ManagementSnapshotV2,
};

pub(crate) fn projection(value: &ManagementProjectionV2) -> Result<(), ContractError> {
    let lifetime = value
        .expires_at_epoch_s
        .checked_sub(value.issued_at_epoch_s)
        .ok_or(ContractError::Invalid)?;
    let valid = value.schema == MANAGEMENT_PROJECTION_SCHEMA
        && id(&value.projection_id, 128)
        && id(&value.request_id, 128)
        && lower_hex(&value.command_digest_sha256, 32)
        && id(&value.issuer, 256)
        && id(&value.audience, 256)
        && id(&value.service_id, 128)
        && reference(&value.pairwise_subject)
        && reference(&value.opaque_account_ref)
        && reference(&value.current_device_ref)
        && reference(&value.current_session_ref)
        && value.subject_revocation_epoch > 0
        && value.service_revocation_epoch > 0
        && value.device_revocation_epoch > 0
        && value.session_revocation_epoch > 0
        && value.device_posture_state == "compliant"
        && value.device_posture_revision > 0
        && reference(&value.device_proof_key_ref)
        && value.snapshot_revision > 0
        && (1..=MANAGEMENT_PROJECTION_MAX_TTL_SECONDS).contains(&lifetime)
        && id(&value.key_id, 128)
        && lower_hex(&value.signature, 64)
        && body_valid(&value.body);
    if valid { bounded(value) } else { invalid() }
}

fn body_valid(value: &ManagementProjectionBodyV2) -> bool {
    match value {
        ManagementProjectionBodyV2::Snapshot { snapshot } => snapshot_valid(snapshot),
        ManagementProjectionBodyV2::Pending { operations } => {
            operations.len() <= 100 && operations.iter().all(operation_valid)
        }
        ManagementProjectionBodyV2::Operation { operation } => operation_valid(operation),
    }
}
fn snapshot_valid(value: &ManagementSnapshotV2) -> bool {
    value.devices.len() <= 100
        && value.sessions.len() <= 1000
        && value.credentials.len() <= 1000
        && value.pending_operations.len() <= 100
        && value.devices.iter().all(device_valid)
        && value.sessions.iter().all(session_valid)
        && value.credentials.iter().all(credential_valid)
        && value.pending_operations.iter().all(operation_valid)
}
fn device_valid(v: &ManagementDeviceV2) -> bool {
    reference(&v.device_ref)
        && v.device_revocation_epoch > 0
        && v.posture_revision > 0
        && references_allow_empty(&v.session_refs, 1000)
        && rfc3339(&v.created_at_rfc3339)
        && rfc3339(&v.updated_at_rfc3339)
}
fn session_valid(v: &ManagementSessionV2) -> bool {
    reference(&v.session_ref)
        && reference(&v.device_ref)
        && v.session_revocation_epoch > 0
        && rfc3339(&v.issued_at_rfc3339)
        && rfc3339(&v.expires_at_rfc3339)
}
fn credential_valid(v: &ManagementCredentialV2) -> bool {
    reference(&v.credential_ref)
        && id(&v.provider, 128)
        && v.revision > 0
        && references_allow_empty(&v.assigned_device_refs, 100)
        && references_allow_empty(&v.scopes, 100)
        && rfc3339(&v.created_at_rfc3339)
        && rfc3339(&v.updated_at_rfc3339)
}
