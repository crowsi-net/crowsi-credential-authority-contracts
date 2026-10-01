use crate::{
    endpoint_approval_fixture::fixture,
    endpoint_approval_verify_call::verify_with_authority,
    endpoint_approval_verify_support::{sign_response, sign_response_as},
};

#[test]
fn authority_response_role_cannot_alias_any_evidence_signing_role() {
    for case in 0..3 {
        let mut value = fixture();
        let key = match case {
            0 => value.assertion_key.clone(),
            1 => value.status_key.clone(),
            _ => value.fresh_key.clone(),
        };
        for exchange in [
            &mut value.selected,
            &mut value.begin,
            &mut value.finish,
            &mut value.current,
        ] {
            sign_response(exchange, &key);
        }
        value.keys.authority = hex::encode(key.verifying_key().to_bytes());
        assert!(value.verify().is_err(), "public key alias {case}");
    }
    let mut id_alias = fixture();
    for exchange in [
        &mut id_alias.selected,
        &mut id_alias.begin,
        &mut id_alias.finish,
        &mut id_alias.current,
    ] {
        sign_response_as(exchange, &id_alias.authority_key, "fresh-key");
    }
    assert!(
        verify_with_authority(
            &id_alias.selected,
            &id_alias.begin,
            &id_alias.finish,
            &id_alias.current,
            &id_alias.prepared,
            &id_alias.browser,
            &id_alias.keys,
            "fresh-key",
            &id_alias.keys.authority,
        )
        .is_err()
    );
}
