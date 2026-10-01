use crate::management_actor_validation::actor_valid;
use crate::management_validation_support::{references, references_allow_empty};
use crate::{ManagementOperationKind, ManagementOperationScopeV2, ManagementOperationV2};

pub(crate) fn operation_valid(value: &ManagementOperationV2) -> bool {
    id(&value.operation_id, 128)
        && digest(&value.intent_digest_sha256)
        && value.state_revision > 0
        && value.created_at_epoch_s < value.expires_at_epoch_s
        && reference(&value.source_device_ref)
        && scope_kind(value)
        && actor_valid(value)
}

fn scope_kind(value: &ManagementOperationV2) -> bool {
    match (&value.kind, &value.scope) {
        (
            ManagementOperationKind::DeviceTransfer,
            ManagementOperationScopeV2::DeviceTransfer {
                target_device_ref,
                credential_refs,
                expected_source_device_revocation_epoch,
            },
        ) => {
            reference(target_device_ref)
                && target_device_ref != &value.source_device_ref
                && references(credential_refs, 100)
                && *expected_source_device_revocation_epoch > 0
        }
        (
            ManagementOperationKind::DeviceRevocation,
            ManagementOperationScopeV2::DeviceRevocation {
                target_device_ref,
                expected_device_revocation_epoch,
                revokes_session_refs,
                rotates_credential_refs,
                preserves_device_refs,
            },
        ) => {
            reference(target_device_ref)
                && *expected_device_revocation_epoch > 0
                && references_allow_empty(revokes_session_refs, 1000)
                && references_allow_empty(rotates_credential_refs, 1000)
                && references_allow_empty(preserves_device_refs, 100)
        }
        (
            ManagementOperationKind::SessionRevocation,
            ManagementOperationScopeV2::SessionRevocation {
                target_session_ref,
                expected_session_revocation_epoch,
                device_ref,
            },
        ) => {
            reference(target_session_ref)
                && *expected_session_revocation_epoch > 0
                && reference(device_ref)
        }
        _ => false,
    }
}

pub(crate) fn id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
pub(crate) fn reference(value: &str) -> bool {
    id(value, 128) && !value.contains('@')
}
pub(crate) fn digest(value: &str) -> bool {
    lower_hex(value, 32)
}
pub(crate) fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
pub(crate) fn base64(value: &str, maximum: usize) -> bool {
    id(value, maximum)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
