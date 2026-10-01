use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAssertionV2 {
    pub credential_id: String,
    pub client_data_json_base64url: String,
    pub authenticator_data_base64url: String,
    pub signature_der_base64url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnOptionsV2 {
    pub attempt_id: String,
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
    pub credential_id: String,
    pub timeout_ms: u64,
    pub expires_at_epoch_s: u64,
    pub command_binding_sha256: String,
}
