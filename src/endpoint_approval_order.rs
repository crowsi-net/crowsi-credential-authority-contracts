use ihat_identity_assertion_contracts::{FreshUvV1, IdentityEvidenceMetadata};

use crate::SignedAuthorityExchangeV1;

pub(crate) fn ordered(
    selected_identity: &SignedAuthorityExchangeV1,
    selected_begin: &SignedAuthorityExchangeV1,
    finish: &SignedAuthorityExchangeV1,
    current_identity: &SignedAuthorityExchangeV1,
    current: &IdentityEvidenceMetadata,
    fresh: &FreshUvV1,
) -> bool {
    let generations = [
        selected_identity.response.config_generation,
        selected_begin.response.config_generation,
        finish.response.config_generation,
        current_identity.response.config_generation,
    ];
    let response_times = [
        selected_identity.response.issued_at_epoch_s,
        selected_begin.response.issued_at_epoch_s,
        finish.response.issued_at_epoch_s,
        current_identity.response.issued_at_epoch_s,
    ];
    generations.windows(2).all(|pair| pair[0] <= pair[1])
        && response_times.windows(2).all(|pair| pair[0] <= pair[1])
        && fresh.issued_at_epoch_s <= current.assertion.issued_at_epoch_s
        && fresh.issued_at_epoch_s <= current.current_status.issued_at_epoch_s
        && current.assertion.issued_at_epoch_s <= current_identity.response.issued_at_epoch_s
        && current.current_status.issued_at_epoch_s <= current_identity.response.issued_at_epoch_s
}
