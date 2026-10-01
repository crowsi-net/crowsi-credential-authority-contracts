use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::*;

use crate::endpoint_envelope::identity;
pub(crate) use crate::endpoint_finish_uv_values::finish_uv_exchange;
pub(crate) use crate::endpoint_management_values::{
    assertion, browser, exchange, identity_exchange, uv_options,
};

pub(crate) fn actor(device: &str, session: char) -> IdentityEvidenceMetadata {
    let mut value = identity();
    value.assertion.device_id = device.into();
    value.current_status.device_id = device.into();
    value.assertion.device_proof_key_ref = format!("proof-{device}");
    value.current_status.device_proof_key_ref = value.assertion.device_proof_key_ref.clone();
    value.assertion.session_ref = sref(session);
    value.current_status.session_ref = value.assertion.session_ref.clone();
    value.assertion.nonce = format!("identity-nonce-{device}");
    value.current_status.nonce = value.assertion.nonce.clone();
    value.assertion.key_id = format!("identity-key-{device}");
    value.current_status.key_id = format!("status-key-{device}");
    value
}

pub(crate) fn sref(value: char) -> String {
    format!("sref_{}", value.to_string().repeat(64))
}

pub(crate) fn fresh(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    proof_id: &str,
    credential_id: &str,
) -> FreshUvV1 {
    let epochs = &identity.assertion.revocation_epochs;
    FreshUvV1 {
        schema: FRESH_UV_SCHEMA.into(),
        proof_id: proof_id.into(),
        credential_id: credential_id.into(),
        authenticator_key_fingerprint: "77".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 120,
        challenge: "options-challenge".into(),
        attempt_id: format!("attempt-{credential_id}"),
        identity_nonce: identity.assertion.nonce.clone(),
        source_device_id: identity.assertion.device_id.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        session_ref: identity.assertion.session_ref.clone(),
        operation_digest_sha256: endpoint_operation_digest(prepared).expect("digest"),
        subject_epoch: epochs.subject,
        service_epoch: epochs.service,
        device_epoch: epochs.device,
        session_epoch: epochs.session,
        account_binding_sha256: "55".repeat(32),
        key_id: format!("uv-key-{credential_id}"),
        signature: "11".repeat(64),
    }
}

pub(crate) fn authentication(value: &FreshUvV1) -> FreshAuthenticationDto {
    FreshAuthenticationDto {
        proof_id: value.proof_id.clone(),
        authenticator_id: value.credential_id.clone(),
        authenticator_key_fingerprint: value.authenticator_key_fingerprint.clone(),
        kind: value.kind,
        user_verified: value.user_verified,
        issued_at_epoch_s: value.issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        session_ref: value.session_ref.clone(),
        operation_digest_sha256: value.operation_digest_sha256.clone(),
        subject_epoch: value.subject_epoch,
        service_epoch: value.service_epoch,
        device_epoch: value.device_epoch,
        session_epoch: value.session_epoch,
    }
}
