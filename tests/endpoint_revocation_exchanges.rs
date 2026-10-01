use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::*;

use crate::endpoint_revocation_values::{authentication, exchange};

pub(crate) fn begin(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    cross: bool,
) -> SignedAuthorityExchangeV1 {
    let command = AuthorityCommand::BeginDeviceRevocation(BeginDeviceRevocationCommand {
        command_id: revocation_begin_command_id(prepared).expect("id"),
        finalize_command_id: prepared.operation_id.clone(),
        service_id: "service-a".into(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        source_device_id: "device-a".into(),
        source_session_ref: prepared.source_session_ref.clone(),
        target_device_id: if cross { "device-b" } else { "device-a" }.into(),
        expected_device_epoch: 1,
        identity_nonce: fresh.identity_nonce.clone(),
        sender_proof_id: "sender-proof-a".into(),
        authentication: authentication(fresh),
    });
    let sender = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: "sender-proof-a".into(),
        key_id: "sender-key-a".into(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 120,
        binding_sha256: String::new(),
        signature: "22".repeat(64),
    };
    let result = RevocationCeremonyMetadata {
        attempt_id: "revocation-attempt".into(),
        finalize_command_id: prepared.operation_id.clone(),
        target_digest: "33".repeat(32),
        expires_at_epoch_s: 400,
        independent_approval_required: cross,
        state: if cross {
            RevocationCeremonyStateDto::AwaitingIndependentApproval
        } else {
            RevocationCeremonyStateDto::ReadyToFinalize
        },
        approval_nonce: cross.then(|| "approval-nonce".into()),
    };
    exchange(
        "begin-request",
        command,
        vec![
            AuthorityEvidence::FreshUv(fresh.clone()),
            AuthorityEvidence::Signed(sender),
        ],
        AuthorityResult::RevocationBegun(result),
        100,
    )
}

pub(crate) fn approval(
    prepared: &EndpointPreparedOperationV2,
    identity: &IdentityEvidenceMetadata,
    begin: &SignedAuthorityExchangeV1,
) -> SignedAuthorityExchangeV1 {
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(metadata),
    } = &begin.response.outcome
    else {
        unreachable!()
    };
    let command = AuthorityCommand::ApproveRevocation(ApproveRevocationCommand {
        command_id: revocation_approval_command_id(prepared, "device-c").expect("id"),
        finalize_command_id: prepared.operation_id.clone(),
        attempt_id: metadata.attempt_id.clone(),
        approval_nonce: metadata.approval_nonce.clone().expect("nonce"),
        approval_proof_id: "approval-proof-c".into(),
        approval_role: ApprovalRoleDto::RecoveryApproval,
        authority_id: "recovery-authority-c".into(),
        approver_device_id: identity.assertion.device_id.clone(),
    });
    let proof = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RecoveryApproval,
        proof_id: "approval-proof-c".into(),
        key_id: "recovery-key-c".into(),
        issued_at_epoch_s: 102,
        expires_at_epoch_s: 122,
        binding_sha256: String::new(),
        signature: "44".repeat(64),
    };
    let result = RevocationApprovalMetadata {
        attempt_id: metadata.attempt_id.clone(),
        finalize_command_id: prepared.operation_id.clone(),
        approval_count: 1,
        ready_to_finalize: true,
        state: RevocationCeremonyStateDto::ReadyToFinalize,
    };
    exchange(
        "approval-request",
        command,
        vec![AuthorityEvidence::Signed(proof)],
        AuthorityResult::RevocationApproved(result),
        102,
    )
}

pub(crate) fn final_exchange(
    prepared: &EndpointPreparedOperationV2,
    issued: u64,
) -> SignedAuthorityExchangeV1 {
    let ManagementIntentV2::DeviceRevocation {
        target_device_ref, ..
    } = &prepared.intent
    else {
        unreachable!()
    };
    let command = AuthorityCommand::RevokeDeviceByRef(RevokeDeviceByRefCommand {
        command_id: prepared.operation_id.clone(),
        service_id: "service-a".into(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        target_device_id: target_device_ref.clone(),
        expected_device_epoch: 1,
        authority_id: "runtime-revocation-key".into(),
    });
    let result = DeviceRevocationMetadata {
        target_digest: "33".repeat(32),
        previous_device_epoch: 1,
        current_device_epoch: 2,
        revoked_session_count: 2,
        audit_sequence: 9,
    };
    exchange(
        "final-request",
        command,
        vec![],
        AuthorityResult::DeviceRevocation(result),
        issued,
    )
}
