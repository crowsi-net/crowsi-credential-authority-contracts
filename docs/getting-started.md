# Using crowsi-credential-authority-contracts

Exchange credential-authority requests without placing secret values in the contract.

## Before you start

These types carry references and evidence. Custody and authorization remain with their configured services.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Represent device, grant and credential-reference relationships.
- Validate bounded proof and operation envelopes.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
