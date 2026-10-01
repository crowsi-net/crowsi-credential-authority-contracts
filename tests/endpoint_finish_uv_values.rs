use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, FinishFreshUvCommand, FreshUvV1,
};

pub(crate) fn finish_uv_exchange(value: &FreshUvV1) -> SignedAuthorityExchangeV1 {
    crate::endpoint_management_values::exchange(
        &format!("finish-{}", value.attempt_id),
        AuthorityCommand::FinishFreshUserVerification(FinishFreshUvCommand {
            command_id: format!("finish-{}", value.attempt_id),
            attempt_id: value.attempt_id.clone(),
            credential_id: value.credential_id.clone(),
            client_data_json_base64url: "e30".into(),
            authenticator_data_base64url: "AA".into(),
            signature_der_base64url: "MA".into(),
        }),
        vec![],
        AuthorityResult::FreshUvFinished {
            document: value.clone(),
        },
        value.issued_at_epoch_s,
    )
}
