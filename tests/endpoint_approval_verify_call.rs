use crowsi_credential_authority_contracts::*;

use crate::endpoint_approval_verify_support::PublicKeys;

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    selected: &SignedAuthorityExchangeV1,
    begin: &SignedAuthorityExchangeV1,
    finish: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    browser: &ManagementCommandV2,
    keys: &PublicKeys,
) -> Result<(), ContractError> {
    verify_with_authority(
        selected,
        begin,
        finish,
        current,
        prepared,
        browser,
        keys,
        "authority-key",
        &keys.authority,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_with_authority(
    selected: &SignedAuthorityExchangeV1,
    begin: &SignedAuthorityExchangeV1,
    finish: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    browser: &ManagementCommandV2,
    keys: &PublicKeys,
    authority_key_id: &str,
    authority_public_key: &str,
) -> Result<(), ContractError> {
    let fresh = fresh_uv_from_finish_exchange(finish, browser)?;
    verify_endpoint_approval_at(
        selected,
        begin,
        finish,
        current,
        prepared,
        browser,
        &EndpointAuthorityResponseTrustV2 {
            minimum_config_generation: 1,
            key_id: authority_key_id,
            public_key_hex: authority_public_key,
        },
        &EndpointIdentityTrustV2 {
            issuer: "ihat-authority",
            audience: "crowsi-management",
            assertion_key_id: "assertion-key",
            assertion_public_key_hex: &keys.assertion,
            current_status_key_id: "status-key",
            current_status_public_key_hex: &keys.status,
            now_epoch_s: 145,
        },
        &EndpointFreshUvTrustV2 {
            account_binding_sha256: &fresh.account_binding_sha256,
            key_id: "fresh-key",
            public_key_hex: &keys.fresh,
            now_epoch_s: 145,
        },
    )
    .map(|_| ())
}
