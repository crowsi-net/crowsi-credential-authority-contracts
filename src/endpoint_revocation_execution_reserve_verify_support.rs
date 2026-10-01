fn response_context(
    value: &EndpointRevocationExecutionReservationV1,
    request: &EndpointRevocationExecutionReserveRequestV1,
    trust: &EndpointRevocationExecutionReservationTrustV1<'_>,
) -> bool {
    value.pre_final_state_revision == request.expected_state_revision
        && value.reserved_state_revision == request.expected_state_revision.saturating_add(1)
        && value.operation.operation_id == request.operation_id
        && crate::endpoint_prepared_lookup_binding::operation_prepared(
            &value.operation,
            &request.prepared,
        )
        && value.operation.state_revision == value.reserved_state_revision
        && value.operation.actor.role == crate::RequiredActorRole::ReconcileOnly
        && value.operation.actor.required_actor_device_ref.is_none()
        && value
            .operation
            .actor
            .required_approval_authority_ref
            .is_none()
        && value.operation.actor.excluded_actor_device_refs.is_empty()
        && value.operation.reconcile_digest.as_deref() == Some(&request.reconcile_digest)
        && value.snapshot_revision >= trust.minimum_snapshot_revision
        && value.reservation_config_generation >= trust.minimum_reservation_config_generation
        && value.config_generation >= trust.minimum_config_generation
        && value.issuer == trust.issuer
        && value.audience == trust.audience
        && value.key_id == trust.key_id
        && value.token.key_id == trust.reservation_key_id
        && value.token.issued_at_epoch_s <= value.issued_at_epoch_s
        && value.issued_at_epoch_s <= trust.now_epoch_s
        && trust.now_epoch_s < value.expires_at_epoch_s
        && value.token.issued_at_epoch_s <= trust.now_epoch_s
}

fn begin_metadata(
    value: &crate::SignedAuthorityExchangeV1,
) -> Result<&ihat_identity_assertion_contracts::RevocationCeremonyMetadata, ContractError> {
    match &value.response.outcome {
        ihat_identity_assertion_contracts::ResponseOutcome::Committed {
            result: ihat_identity_assertion_contracts::AuthorityResult::RevocationBegun(result),
        } => Ok(result),
        _ => Err(ContractError::Invalid),
    }
}
