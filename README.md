# Crowsi credential authority contracts

Closed, secret-free DTO and canonical proof bytes. This crate owns no authority store, policy,
provider executor, custody implementation, transport, or account correlation state.

Management v2 is the current-only browser/endpoint contract. Requests contain only user intent,
opaque operation IDs, CAS revisions, and public WebAuthn assertion bytes. They cannot contain
caller-made identity assertions, current status, FreshUv, target proof, account ID, session ID, or
private keys. Endpoint agents obtain and verify those factors directly from their local custody and
remote authorities.

Every snapshot, pending list, options response, and operation result is carried in a 30-second
`ManagementProjectionV2` signed by the Credential Authority. The signature covers the current
endpoint device/session, service pairwise subject, opaque service owner, snapshot revision, device
and session revocation epochs, operation scope/state, required actor, excluded device refs, public
WebAuthn options, closed reason, and reconcile digest. Passive refresh may reuse the same valid
projection; mutations use the included state revision and authority journal.

Owner recovery uses a mnemonic seed phrase as the primary recovery method, but this crate exposes
only `OwnerRecoveryCustodyReceiptV1`: recovery identity, custody provider, key revision, state and a
SHA-256 root fingerprint. Mnemonic words and derived private keys have no wire field. Their
generation, confirmation and use remain inside a purpose-specific Crowsi custody provider; Hatter,
HATs, Zixcel orchestration and browser projections receive public proof metadata only.
