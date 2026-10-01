//! Closed metadata and proof documents shared by Crowsi credential clients and authority hosts.

#![forbid(unsafe_code)]
mod endpoint_actor_binding;
mod endpoint_approval_context;
mod endpoint_approval_order;
mod endpoint_approval_verify;
mod endpoint_cancel_recovery_verify;
mod endpoint_envelope;
mod endpoint_envelope_types;
mod endpoint_envelope_validation;
mod endpoint_exchange;
mod endpoint_finish_uv;
mod endpoint_fresh_verify;
mod endpoint_identity_binding;
mod endpoint_identity_context;
mod endpoint_identity_operation;
mod endpoint_identity_phases;
mod endpoint_identity_verify;
mod endpoint_independent_revocation_finalize;
mod endpoint_independent_revocation_finalize_validation;
mod endpoint_independent_revocation_finalize_verify;
mod endpoint_independent_revocation_pre_final;
mod endpoint_independent_revocation_pre_final_validation;
mod endpoint_independent_revocation_pre_final_verify;
mod endpoint_prepared_lookup;
mod endpoint_prepared_lookup_binding;
mod endpoint_prepared_lookup_decode;
mod endpoint_prepared_lookup_policy;
mod endpoint_prepared_lookup_required;
mod endpoint_prepared_lookup_revocation;
mod endpoint_prepared_lookup_verify;
mod endpoint_reserved_revocation_final_verify;
mod endpoint_revocation_approval;
mod endpoint_revocation_begin;
mod endpoint_revocation_begin_binding;
mod endpoint_revocation_binding;
mod endpoint_revocation_chain;
include!("lib_revocation_execution_cancel_modules.rs");
mod endpoint_revocation_execution_reserve;
mod endpoint_revocation_execution_reserve_attach;
mod endpoint_revocation_execution_reserve_canonical;
mod endpoint_revocation_execution_reserve_digest;
mod endpoint_revocation_execution_reserve_validation;
mod endpoint_revocation_execution_reserve_verify;
mod endpoint_revocation_final;
mod endpoint_revocation_finalize;
mod endpoint_revocation_finalize_acceptance;
mod endpoint_revocation_finalize_validation;
mod endpoint_revocation_finalize_verify;
mod endpoint_revocation_pre_final_verify;
mod endpoint_revocation_requirements;
mod endpoint_target_binding;
mod error;
mod management_actor_validation;
mod management_crypto;
mod management_decode;
mod management_operation;
mod management_operation_validation;
mod management_projection;
mod management_request;
mod management_request_validation;
mod management_snapshot;
mod management_validation;
mod management_validation_support;
mod management_verify;
mod management_webauthn;
mod owner_recovery_custody;
mod target_proof;

pub use endpoint_approval_verify::{
    EndpointAuthorityResponseTrustV2, VerifiedEndpointApprovalV2,
    verify as verify_endpoint_approval_at,
};
pub use endpoint_cancel_recovery_verify::*;
pub use endpoint_envelope::*;
pub use endpoint_envelope_types::*;
pub use endpoint_exchange::{
    identity_evidence_from_exchange, validate_authority_exchange, verify_authority_exchange_at,
    verify_authority_exchange_historic,
};
pub use endpoint_finish_uv::{fresh_uv_from_finish_exchange, validate_finish_uv_continuity};
pub use endpoint_fresh_verify::{EndpointFreshUvTrustV2, verify as verify_endpoint_fresh_uv_at};
pub use endpoint_identity_verify::{
    EndpointIdentityTrustV2, verify as verify_endpoint_identity_at,
};
pub use endpoint_independent_revocation_finalize::*;
pub use endpoint_independent_revocation_finalize_verify::*;
pub use endpoint_independent_revocation_pre_final::*;
pub use endpoint_independent_revocation_pre_final_verify::*;
pub use endpoint_prepared_lookup::*;
pub use endpoint_prepared_lookup_verify::verify_endpoint_prepared_lookup_response_at;
pub use endpoint_reserved_revocation_final_verify::*;
pub use endpoint_revocation_binding::{
    revocation_approval_command_id, revocation_begin_command_id, validate_revocation_ceremony_at,
};
pub use endpoint_revocation_execution_reserve::*;
pub use endpoint_revocation_execution_reserve_attach::*;
pub use endpoint_revocation_execution_reserve_canonical::*;
pub use endpoint_revocation_execution_reserve_digest::*;
pub use endpoint_revocation_execution_reserve_verify::*;
pub use endpoint_revocation_finalize::*;
pub use endpoint_revocation_finalize_acceptance::*;
pub use endpoint_revocation_finalize_verify::*;
pub use endpoint_revocation_pre_final_verify::*;
pub use endpoint_target_binding::{
    context as validate_target_device_proof_context,
    freshness as validate_target_device_proof_freshness,
    verify_at as verify_target_device_proof_at,
};
pub use error::ContractError;
pub use management_crypto::{canonical_management_projection, management_command_digest};
pub use management_decode::{
    decode_management_projection_strict, decode_management_request_strict,
};
pub use management_operation::*;
pub use management_projection::*;
pub use management_request::*;
pub use management_snapshot::*;
pub use management_verify::verify_management_projection_at;
pub use management_webauthn::*;
pub use owner_recovery_custody::*;
pub use target_proof::{TargetDeviceProofBindingV2, target_device_proof_digest};
