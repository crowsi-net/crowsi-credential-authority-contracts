use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::*;

use crate::endpoint_revocation_values::{authentication, exchange, sref};

pub(crate) fn begin(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
) -> SignedAuthorityExchangeV1 {
    let command = AuthorityCommand::BeginSessionRevocation(BeginSessionRevocationCommand {
        command_id: revocation_begin_command_id(prepared).expect("id"),
        finalize_command_id: prepared.operation_id.clone(),
        service_id: "service-a".into(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        source_device_id: "device-a".into(),
        source_session_ref: prepared.source_session_ref.clone(),
        target_session_ref: sref('b'),
        expected_session_epoch: 1,
        identity_nonce: fresh.identity_nonce.clone(),
        sender_proof_id: "session-sender-proof".into(),
        authentication: authentication(fresh),
    });
    let sender = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: "session-sender-proof".into(),
        key_id: "session-sender-key".into(),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 120,
        binding_sha256: String::new(),
        signature: "22".repeat(64),
    };
    let result = RevocationCeremonyMetadata {
        attempt_id: "session-attempt".into(),
        finalize_command_id: prepared.operation_id.clone(),
        target_digest: "ab".repeat(32),
        expires_at_epoch_s: 400,
        independent_approval_required: true,
        state: RevocationCeremonyStateDto::AwaitingIndependentApproval,
        approval_nonce: Some("session-approval-nonce".into()),
    };
    exchange(
        "session-begin",
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
    actor: &str,
    begin: &SignedAuthorityExchangeV1,
) -> SignedAuthorityExchangeV1 {
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(metadata),
    } = &begin.response.outcome
    else {
        unreachable!()
    };
    let proof_id = format!("approval-proof-{actor}");
    let command = AuthorityCommand::ApproveRevocation(ApproveRevocationCommand {
        command_id: revocation_approval_command_id(prepared, actor).expect("id"),
        finalize_command_id: prepared.operation_id.clone(),
        attempt_id: metadata.attempt_id.clone(),
        approval_nonce: metadata.approval_nonce.clone().expect("nonce"),
        approval_proof_id: proof_id.clone(),
        approval_role: ApprovalRoleDto::RecoveryApproval,
        authority_id: "recovery-authority-c".into(),
        approver_device_id: actor.into(),
    });
    let proof = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RecoveryApproval,
        proof_id,
        key_id: format!("recovery-key-{actor}"),
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
        "session-approval",
        command,
        vec![AuthorityEvidence::Signed(proof)],
        AuthorityResult::RevocationApproved(result),
        102,
    )
}

pub(crate) fn final_revoke(prepared: &EndpointPreparedOperationV2) -> SignedAuthorityExchangeV1 {
    let command = AuthorityCommand::RevokeSessionByRef(RevokeSessionByRefCommand {
        command_id: prepared.operation_id.clone(),
        service_id: "service-a".into(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        session_ref: sref('b'),
        expected_epoch: 1,
        authority_id: "runtime-revocation-key".into(),
    });
    let result = RevocationMetadata {
        target_digest: "ab".repeat(32),
        previous_epoch: 1,
        current_epoch: 2,
        audit_sequence: 10,
    };
    exchange(
        "session-final",
        command,
        vec![],
        AuthorityResult::Revocation(result),
        103,
    )
}
