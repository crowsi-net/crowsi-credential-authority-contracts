use crate::management_operation_validation::{base64, digest, id, reference};
use crate::management_validation_support::{bounded, invalid, references};
use crate::{
    ContractError, MANAGEMENT_REQUEST_SCHEMA, ManagementCommandV2, ManagementIntentV2,
    ManagementRequestV2, WebAuthnAssertionV2,
};

pub(crate) fn request(value: &ManagementRequestV2) -> Result<(), ContractError> {
    if value.schema != MANAGEMENT_REQUEST_SCHEMA || !id(&value.request_id, 128) {
        return invalid();
    }
    let valid = match &value.command {
        ManagementCommandV2::Snapshot { service_id }
        | ManagementCommandV2::PendingList { service_id } => id(service_id, 128),
        ManagementCommandV2::SourceOptions { intent } => intent_valid(intent),
        ManagementCommandV2::SourceApprove {
            operation_id,
            expected_state_revision,
            attempt_id,
            assertion,
        }
        | ManagementCommandV2::TargetApprove {
            operation_id,
            expected_state_revision,
            attempt_id,
            assertion,
        }
        | ManagementCommandV2::ApproveRevocation {
            operation_id,
            expected_state_revision,
            attempt_id,
            assertion,
        } => {
            id(operation_id, 128)
                && *expected_state_revision > 0
                && id(attempt_id, 128)
                && assertion_valid(assertion)
        }
        ManagementCommandV2::TargetOptions {
            operation_id,
            expected_state_revision,
        }
        | ManagementCommandV2::ApprovalOptions {
            operation_id,
            expected_state_revision,
        }
        | ManagementCommandV2::Cancel {
            operation_id,
            expected_state_revision,
        } => id(operation_id, 128) && *expected_state_revision > 0,
        ManagementCommandV2::Reconcile {
            operation_id,
            expected_state_revision,
            reconcile_digest,
        } => id(operation_id, 128) && *expected_state_revision > 0 && digest(reconcile_digest),
    };
    if valid { bounded(value) } else { invalid() }
}

fn intent_valid(value: &ManagementIntentV2) -> bool {
    match value {
        ManagementIntentV2::DeviceTransfer {
            service_id,
            target_device_ref,
            credential_refs,
            expected_snapshot_revision,
            nonce,
        } => {
            id(service_id, 128)
                && reference(target_device_ref)
                && references(credential_refs, 100)
                && *expected_snapshot_revision > 0
                && id(nonce, 128)
        }
        ManagementIntentV2::DeviceRevocation {
            service_id,
            target_device_ref,
            expected_device_revocation_epoch,
            expected_snapshot_revision,
            nonce,
        } => {
            id(service_id, 128)
                && reference(target_device_ref)
                && *expected_device_revocation_epoch > 0
                && *expected_snapshot_revision > 0
                && id(nonce, 128)
        }
        ManagementIntentV2::SessionRevocation {
            service_id,
            target_session_ref,
            expected_session_revocation_epoch,
            expected_snapshot_revision,
            nonce,
        } => {
            id(service_id, 128)
                && reference(target_session_ref)
                && *expected_session_revocation_epoch > 0
                && *expected_snapshot_revision > 0
                && id(nonce, 128)
        }
    }
}

fn assertion_valid(value: &WebAuthnAssertionV2) -> bool {
    id(&value.credential_id, 128)
        && base64(&value.client_data_json_base64url, 16_384)
        && base64(&value.authenticator_data_base64url, 4096)
        && base64(&value.signature_der_base64url, 4096)
}
