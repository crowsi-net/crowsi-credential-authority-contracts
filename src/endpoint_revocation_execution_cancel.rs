use ihat_identity_assertion_contracts::{AuthorityRequestV1, SignedEvidenceV1};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    ContractError, EndpointManagementEnvelopeV2, EndpointPreparedOperationV2,
    ManagementOperationV2, SignedAuthorityExchangeV1,
};

pub const ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-execution-cancel-request/v1";
pub const ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_SCHEMA: &str =
    "crowsi://credential-authority/endpoint-revocation-execution-cancellation/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionCancelRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub operation_id: String,
    pub expected_cancelled_state_revision: u64,
    pub pre_final_acceptance_request_sha256: String,
    pub cancel_envelope: EndpointManagementEnvelopeV2,
    pub prepared: EndpointPreparedOperationV2,
    pub begin_exchange: SignedAuthorityExchangeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRevocationExecutionCancellationV1 {
    pub schema: String,
    pub cancellation_id: String,
    pub cancellation_request_sha256: String,
    pub cancel_envelope_digest_sha256: String,
    pub pre_final_acceptance_request_sha256: String,
    pub prepared_operation_digest_sha256: String,
    pub opaque_owner_ref: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub source_device_ref: String,
    pub source_session_ref: String,
    pub target_digest_sha256: String,
    pub begin_exchange_digest_sha256: String,
    pub begin_command_digest_sha256: String,
    pub finalize_command_id: String,
    pub cancelled_state_revision: u64,
    #[serde(deserialize_with = "required_optional_string")]
    pub execution_reservation_id: Option<String>,
    pub cancellation_config_generation: u64,
    pub cancellation_accepted_revision: u64,
    pub operation: ManagementOperationV2,
    pub snapshot_revision: u64,
    pub cancel_pending_request: AuthorityRequestV1,
    pub token: SignedEvidenceV1,
    pub issuer: String,
    pub audience: String,
    pub config_generation: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub key_id: String,
    pub signature: String,
}

fn required_optional_string<'de, D>(value: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(value)
}

include!("endpoint_revocation_execution_cancel_decode.rs");
