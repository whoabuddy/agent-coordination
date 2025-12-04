# ERC-8001 Agent Coordination (Stacks SIP-XXX)

[![Status: Draft](https://img.shields.io/badge/Status-Draft-yellow.svg)](https://github.com/) [![License: CC0-1.0](https://img.shields.io/badge/License-CC0--1.0-lightgrey.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

## Overview

**ERC-8001** defines a minimal, single-chain primitive for multi-party agent coordination on Ethereum. This repository ports it faithfully to **Stacks/Clarity** as **SIP-XXX**.

- **Proposer** posts an EIP-712 `AgentIntent` (no sig needed; tx proves).
- **Participants** sign `AcceptanceAttestation`s (secp256k1-recover verified).
- Once **all acceptances** are fresh, execute with `payload` (sha256 verified).
- Lifecycle: `Proposed` → `Ready` → `Executed` / `Cancelled` / `Expired`.
- **Max 20 participants** (decidable O(20²) loops).
- **No execution logic** (modules extend).

**Reference**: [Ethereum EIP-8001](https://eips.ethereum.org/EIPS/eip-8001)

## Specification

- **SIP Text**: [docs/SIP-ERC-8001.md](docs/SIP-ERC-8001.md)
- **Clarity Contract**: [contracts/erc-8001.clar](contracts/erc-8001.clar)
- **Trait**: `IAgentCoordination` (propose/accept/execute/cancel + getters)
- **EIP-712 Domain**: `{name: "ERC-8001", version: "1", chainId, verifyingContract: sha256("stacks-sip-erc8001-ref-v1")}`
- **Hashing**: sha256 native; BE32 uint pack; sorted principals (buff21 lex); hash160 concat.
- **Errors/Events/Status**: Canonical per spec.

**Deprecated**: [docs/SIP-ERC-8001-old-reference.clar](docs/SIP-ERC-8001-old-reference.clar)

## Quickstart

### Prerequisites
- [Node.js](https://nodejs.org/) (for TS tests)
- [Clarinet](https://docs.clarinet.dev/) (Stacks dev tool)

### Install & Test
```bash
npm install
npm test  # Vitest TS suite (tests/erc-8001.test.ts)
clarinet test  # Clarinet integration
```

### Deploy (Devnet)
```bash
clarinet integrate settings/Devnet.toml
```

Config: [Clarinet.toml](Clarinet.toml), [.vscode](/.vscode/), [tsconfig.json](tsconfig.json)

## Key Implementation Notes

- **Storage**: `intents` (hash → state), `agent-nonces`, `acceptances`.
- **Verification**: `secp256k1-recover?` → `principal-of?` == tx-sender.
- **Sorting**: Strict ascending `buff21` (v1 + hash160); unique/no-dups.
- **Expiry**: Intent + per-accept; auto-`EXPIRED` in status.
- **Limits**: `(list 20 principal)`, `(buff 1024)` payload/execution-data.
- **Constants**: Exposed via `get-eip712-constants` (off-chain compat).

## Modules / Extensions

Core is **state machine only**. Add:
- **Privacy**: Commit-reveal/TEE.
- **Thresholds**: Subsets.
- **Bonding/Slash**: Econ security.
- **Cross-chain**: Bridges.
- **Exec**: Swap/atomic/guard.

## Security

- **Replay**: Agent nonces + domain/chainId.
- **Sig Malleability**: secp256k1 native (low-S safe).
- **Front-run**: Public propose; use short expiry/encryption.
- **Audit**: Max-20 decidable; ref impl tested.

## License
[CC0-1.0](LICENSE) (public domain).

**Author**: [Kwame Bryan](mailto:kwame.bryan@gmail.com)
