fn digests(value: &EndpointRevocationExecutionReservationV1) -> bool {
    [
        &value.reservation_request_sha256,
        &value.original_command_digest_sha256,
        &value.prepared_operation_digest_sha256,
        &value.reconcile_digest,
        &value.target_digest_sha256,
        &value.begin_exchange_digest_sha256,
        &value.final_command_digest_sha256,
    ]
    .into_iter()
    .all(|item| digest(item))
        && value
            .approval_exchange_digest_sha256
            .as_ref()
            .is_none_or(|item| digest(item))
}

fn references(value: &EndpointRevocationExecutionReservationV1) -> bool {
    id(&value.original_request_id, 128)
        && reference(&value.opaque_owner_ref)
        && id(&value.service_id, 128)
        && reference(&value.pairwise_subject)
        && reference(&value.source_device_ref)
        && reference(&value.finalizer_device_ref)
        && id(&value.issuer, 256)
        && id(&value.audience, 256)
        && id(&value.key_id, 128)
        && lower_hex(&value.signature, 64)
}

fn revisions(value: &EndpointRevocationExecutionReservationV1) -> bool {
    value.pre_final_state_revision > 0
        && value.pre_final_state_revision.checked_add(1) == Some(value.reserved_state_revision)
        && value.reservation_config_generation > 0
        && value.config_generation == value.reservation_config_generation
        && value.snapshot_revision > 0
        && value.token.issued_at_epoch_s <= value.issued_at_epoch_s
        && value.operation.state == ManagementOperationState::RevocationExecutionReserved
        && value.operation.state_revision == value.reserved_state_revision
}

fn token(value: &EndpointRevocationExecutionReservationV1) -> bool {
    value.token.schema == SIGNED_EVIDENCE_SCHEMA
        && value.token.role == VerificationRole::RevocationExecutionReservation
        && value.token.proof_id == value.reservation_id
        && value.token.binding_sha256 == value.final_command_digest_sha256
        && id(&value.token.key_id, 128)
        && lower_hex(&value.token.signature, 64)
        && crate::endpoint_revocation_execution_reservation_id(value)
            .is_ok_and(|item| item == value.reservation_id)
}
