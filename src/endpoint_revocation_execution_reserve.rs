use ihat_identity_assertion_contracts::{AuthorityRequestV1, SignedEvidenceV1};
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, EndpointPreparedOperationV2, ManagementOperationV2, ManagementRequestV2,
    SignedAuthorityExchangeV1,
};

pub const ENDPOINT_REVOCATION_EXECUTION_RESERVE_REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-execution-reserve-request/v1";
pub const ENDPOINT_REVOCATION_EXECUTION_RESERVATION_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-execution-reservation/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionReserveRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub expected_state_revision: u64,
    pub reconcile_digest: String,
    pub original_request: ManagementRequestV2,
    pub prepared: EndpointPreparedOperationV2,
    pub pre_final_acceptance_request_sha256: String,
    pub accepted_identity_exchange: SignedAuthorityExchangeV1,
    pub reservation_identity_exchange: SignedAuthorityExchangeV1,
    pub begin_exchange: SignedAuthorityExchangeV1,
    pub approval_exchange: Option<SignedAuthorityExchangeV1>,
    pub final_revoke_request: AuthorityRequestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionReservationV1 {
    pub schema: String,
    pub reservation_id: String,
    pub reservation_request_sha256: String,
    pub original_request_id: String,
    pub original_command_digest_sha256: String,
    pub prepared_operation_digest_sha256: String,
    pub reconcile_digest: String,
    pub opaque_owner_ref: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub source_device_ref: String,
    pub finalizer_device_ref: String,
    pub target_digest_sha256: String,
    pub begin_exchange_digest_sha256: String,
    pub approval_exchange_digest_sha256: Option<String>,
    pub final_command_digest_sha256: String,
    pub pre_final_state_revision: u64,
    pub reserved_state_revision: u64,
    pub reservation_config_generation: u64,
    pub operation: ManagementOperationV2,
    pub snapshot_revision: u64,
    pub token: SignedEvidenceV1,
    pub issuer: String,
    pub audience: String,
    pub config_generation: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub key_id: String,
    pub signature: String,
}

include!("endpoint_revocation_execution_reserve_decode.rs");
