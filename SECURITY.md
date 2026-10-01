# Security

- This crate contains contracts and canonical verification only. It cannot open an authority store,
  execute a provider or custody backend, terminate mTLS, correlate services, or return secrets.
- `ManagementRequestV2` deliberately has no source/target/approval device-ref override and no signed
  identity evidence field. The endpoint's own mutually authenticated connection determines the actor.
- `ManagementProjectionV2` must be strictly decoded and verified against pinned issuer, audience,
  service, endpoint device, minimum revision, key, and trusted time before UI action gating.
- A target transfer is actionable only when the signed required actor is that target endpoint. A
  cross-device revoke is actionable only for the distinct signed device/recovery authority and lists
  source and target as excluded actors.
- `unknown` is never success. It carries one signed reconcile digest and permits reconcile only.
- Credential projections are metadata-only and use closed `operation-only`, `delegated-token`, or
  `certificate` classes, numeric revision/epochs, assigned opaque device refs, scopes, and timestamps.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
