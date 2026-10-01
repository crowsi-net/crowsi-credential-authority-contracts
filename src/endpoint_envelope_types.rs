use ihat_identity_assertion_contracts::{AuthorityRequestV1, AuthorityResponseV1};
use serde::{Deserialize, Serialize};

use crate::{ManagementRequestV2, TargetDeviceProofBindingV2};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPreparedOperationV2 {
    pub operation_id: String,
    pub origin_command_digest_sha256: String,
    pub source_device_ref: String,
    pub source_session_ref: String,
    pub pairwise_subject: String,
    pub opaque_owner_ref: String,
    pub source_identity_nonce: String,
    pub nonce: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub intent: crate::ManagementIntentV2,
    pub revocation: Option<RevocationRequirementsV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequirementsV2 {
    pub target_device_ref: String,
    pub required_approval_authority_ref: Option<String>,
    pub finalization_authority_id: String,
    pub expected_revoked_session_count: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetDeviceProofV2 {
    pub binding: TargetDeviceProofBindingV2,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityExchangeV1 {
    pub request: AuthorityRequestV1,
    pub response: AuthorityResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationSourceCeremonyV1 {
    pub begin: SignedAuthorityExchangeV1,
    pub final_revoke: Option<SignedAuthorityExchangeV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationIndependentCeremonyV1 {
    pub begin: SignedAuthorityExchangeV1,
    pub approval: SignedAuthorityExchangeV1,
    pub final_revoke: SignedAuthorityExchangeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationIndependentPreFinalCeremonyV1 {
    pub begin: SignedAuthorityExchangeV1,
    pub approval: SignedAuthorityExchangeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum EndpointManagementEvidenceV2 {
    Passive {
        identity_exchange: SignedAuthorityExchangeV1,
    },
    SourceOptions {
        identity_exchange: SignedAuthorityExchangeV1,
        prepared: EndpointPreparedOperationV2,
        uv_options: SignedAuthorityExchangeV1,
    },
    SourceApprove {
        identity_exchange: SignedAuthorityExchangeV1,
        prepared: EndpointPreparedOperationV2,
        finish_uv_exchange: SignedAuthorityExchangeV1,
        revocation_ceremony: Option<RevocationSourceCeremonyV1>,
    },
    ActorOptions {
        identity_exchange: SignedAuthorityExchangeV1,
        prepared: EndpointPreparedOperationV2,
        uv_options: SignedAuthorityExchangeV1,
    },
    TargetApprove {
        identity_exchange: SignedAuthorityExchangeV1,
        prepared: EndpointPreparedOperationV2,
        finish_uv_exchange: SignedAuthorityExchangeV1,
        target_proof: SignedTargetDeviceProofV2,
    },
    IndependentApprove {
        identity_exchange: SignedAuthorityExchangeV1,
        prepared: EndpointPreparedOperationV2,
        finish_uv_exchange: SignedAuthorityExchangeV1,
        revocation_ceremony: RevocationIndependentCeremonyV1,
    },
    Cancel {
        identity_exchange: SignedAuthorityExchangeV1,
        prepared: EndpointPreparedOperationV2,
    },
    Reconcile {
        identity_exchange: SignedAuthorityExchangeV1,
        prepared: EndpointPreparedOperationV2,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointManagementEnvelopeV2 {
    pub schema: String,
    pub browser_request: ManagementRequestV2,
    pub evidence: EndpointManagementEvidenceV2,
}
