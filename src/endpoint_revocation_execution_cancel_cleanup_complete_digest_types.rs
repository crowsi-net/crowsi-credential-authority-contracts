#[derive(Serialize)]
struct StableRequest<'a> {
    schema: &'a str,
    request_id: &'a str,
    operation_id: &'a str,
    cancel_finalize_request: &'a crate::EndpointRevocationExecutionCancelFinalizeRequestV1,
    cleanup: StableCleanup<'a>,
    acknowledge_request: &'a ihat_identity_assertion_contracts::AuthorityRequestV1,
    acknowledge_outcome: &'a ihat_identity_assertion_contracts::ResponseOutcome,
}

#[derive(Serialize)]
struct StableCleanup<'a> {
    schema: &'a str,
    cleanup_id: &'a str,
    cancel_finalize_request_sha256: &'a str,
    cancellation_id: &'a str,
    cancel_pending_command_digest_sha256: &'a str,
    cancel_pending_response_digest_sha256: &'a str,
    source_device_ref: &'a str,
    cleanup_completed_revision: u64,
    cleanup_config_generation: u64,
    operation: &'a crate::ManagementOperationV2,
    acknowledge_request: &'a ihat_identity_assertion_contracts::AuthorityRequestV1,
    token: &'a ihat_identity_assertion_contracts::SignedEvidenceV1,
    issuer: &'a str,
    audience: &'a str,
}

#[derive(Serialize)]
struct Acknowledgement<'a> {
    request: &'a ihat_identity_assertion_contracts::AuthorityRequestV1,
    outcome: &'a ihat_identity_assertion_contracts::ResponseOutcome,
}
