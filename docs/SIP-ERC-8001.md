# Preamble

SIP Number: XXX  
Title: ERC-8001 Agent Coordination Framework (EIP-8001 adapted for Stacks)  
Author: [Kwame Bryan] (<kwame.bryan@gmail.com>)  
Consideration: Technical  
Type: Standard  
Status: Draft  
Created: 28 November 2025  
Licence: CC0-1.0 (Creative Commons Zero v1.0 Universal)  
Sign-off: _(pending)_

# Abstract

This proposal ports Ethereum's ERC-8001 as a Stacks SIP standard primitive for secure multi-party agent coordination. An initiator proposes an **AgentIntent** (EIP-712 typed data), participants submit **AcceptanceAttestation** signatures. Once all acceptances present/fresh, intent **Ready** for execution. Specifies adapted data structs (buff/sha256), status codes, Clarity interface, lifecycle rules. Uses Clarity sha256 + 32-byte big-endian field serialization (ABI-compatible packing). Reference impl `contracts/erc-8001.clar` (max 20 participants, standard principals).

# Licence and Copyright

This SIP is released under the terms of the **Creative Commons CC0 1.0 Universal** licence:contentReference[oaicite:17]{index=17}. By contributing to this SIP, authors agree to dedicate their work to the public domain. The Stacks Open Internet Foundation holds copyright for this document.

# Introduction

As decentralised applications and autonomous agents become more complex, there are many scenarios where a group of independent actors must agree on an action before it is executed. Examples include multi-signature wallet approvals, collaborative trades or arbitrage across DEXs, and MEV (Maximal Extractable Value) mitigation where solvers and bidders coordinate on transaction ordering. In current practice, these often rely on bespoke protocols or off-chain agreements, leading to fragmentation and potential security risks.

ERC-8001 [EIP](https://eips.ethereum.org/EIPS/eip-8001) defines minimal single-chain multi-party coordination: initiator EIP-712 AgentIntent + per-participant EIP-712/1271 acceptances. Executable iff all accept & fresh. This SIP ports faithfully to Stacks/Clarity: sha256 (native), buff structs, principal20-hash160 packed, BE32 fields, tx-sender proves propose (no sig), secp256k1-recover for accepts.

The key idea is that an initiator can propose an intent which enumerates all participants who need to agree. Each participant (including the initiator) produces a digital signature (an **acceptance attestation**) to confirm their agreement under certain conditions. These signatures are collected on-chain. If and only if every listed party’s attestation is present and valid within the allowed time window, the intent is marked as ready to execute. This guarantees that the intended action has unanimous approval from the required set of agents, without needing an off-chain coordinator to aggregate trust.

Privacy and advanced policies (like threshold k-of-n approvals, bond posting, or cross-chain intents) are intentionally **out of scope** for this base standard:contentReference[oaicite:20]{index=20}:contentReference[oaicite:21]{index=21}. The goal is to establish a simple, extensible on-chain core that other modules and protocols can build upon for added functionality.

# Specification

The keywords “MUST”, “SHOULD”, and “MAY” in this document are to be interpreted as described in RFC 2119.

## Status Codes

Implementations MUST use the following canonical status codes for each intent’s lifecycle state:contentReference[oaicite:22]{index=22}:

- `None` (`0`): No record of the intent (default state before proposal).
- `Proposed` (`1`): Intent has been proposed and stored, but not all required acceptances are yet present.
- `Ready` (`2`): **All participants have accepted.** The intent is fully signed and can be executed.
- `Executed` (`3`): Intent was executed successfully (finalised outcome).
- `Cancelled` (`4`): Intent was explicitly cancelled by the initiator and will not execute.
- `Expired` (`5`): Intent expired before execution.

A compliant contract MUST provide a read-only function (e.g. `get-coordination-status(intentId)`) that returns one of these status codes for a given intent. External tools and UI can use these codes to inform users of the intent’s state.

## Data Structures

**AgentIntent** (fields serialized sha256 for intentHash struct-hash):

- `payloadHash` `(buff 32)`: sha256(CoordinationPayload); checked at execute.
- `expiry` `uint`: unix sec > now; intent/execute bound.
- `nonce` `uint`: > get-agent-nonce(agent); replay prot.
- `agentId` `principal`: proposer=tx-sender.
- `coordinationType` `(buff 32)`: domain id e.g. sha256("MEV_SANDWICH_COORD_V1").
- `coordinationValue` `uint`: informational.
- `participants` `(list 20 principal)`: unique strictly ascending hash160; includes agent.

**AcceptanceAttestation** (sig over EIP712-like digest; nonce=0 core):

- `intentHash` `(buff 32)`: intent-struct-hash (not full digest).
- `participant` `principal`: signer=tx-sender.
- `nonce` `uint`: u0 (core; modules MAY).
- `expiry` `uint`: >now at accept/execute.
- `conditionsHash` `(buff 32)`: participant constraints.
- `signature` `(buff 65)`: secp256k1 (recid).

Struct-hash: sha256(TYPEHASH32 + fields32BE); domain-sha256(nameH||verH||chain32BE||verifH); digest=sha256(0x1901||domain||struct).

**CoordinationPayload** (off-chain; sha256=payloadHash; opaque core):

version `(buff 32)`, coordinationType `(buff 32)`, data `(buff ...)`, conditions `(buff 32)`, timestamp `uint`, metadata `(buff ...)`.

## Hashing Semantics (SIP adaptation of EIP-712)

- **participantsHash** = `sha256(concat(p.hash160 for p in participants))`
- **intentStructHash** = `sha256(AGENT_INTENT_TYPEHASH + payloadHash + u64BE32(expiry) + u64BE32(nonce) + addr32(agent) + coordType + u256BE32(value) + participantsHash)`
- **acceptanceStructHash** = `sha256(ACCEPTANCE_TYPEHASH + intentHash + addr32(participant) + u64BE32(nonce=0) + u64BE32(expiry) + conditions)`
- **domainSep** = `sha256(nameH + versionH + chainIdBE32 + verifyingFixedH)`
- **acceptDigest** = `sha256(0x1901 + domainSep + acceptanceStructHash)`
- TYPEHASH = `sha256("AgentIntent(...)")` / `sha256("AcceptanceAttestation(...)")`
- `intentHash` = intentStructHash (used in acceptance.intentHash)

Off-chain sign acceptDigest; on-chain recover-pubkey(principal-of? == tx-sender).

## Signature Semantics and Domain Separation

## Standard Contract Interface

Compliant contracts expose:

```
(define-public (propose-coordination (payload-hash (buff 32)) (expiry uint) (nonce uint) (coord-type (buff 32)) (coord-value uint) (participants (list 20 principal))) (response (buff 32) uint))

(define-public (accept-coordination (intent-hash (buff 32)) (accept-expiry uint) (conditions (buff 32)) (sig (buff 65))) (response bool uint))

(define-public (execute-coordination (intent-hash (buff 32)) (payload (buff 1024)) (execution-data (buff 1024))) (response bool (buff 1024)))

(define-public (cancel-coordination (intent-hash (buff 32)) (reason (string-ascii 34))) (response bool uint))

(define-read-only (get-coordination-status (intent-hash (buff 32))) (response {status: uint, agent: principal, participants: (list 20 principal), accepted-by: (list 20 principal), expiry: uint} uint))

(define-read-only (get-required-acceptances (intent-hash (buff 32))) (response uint uint))

(define-read-only (get-agent-nonce (agent principal)) uint)
```

Events via `print` tuples matching EIP-8001.

By following these semantics, any signature collected under this standard is tightly bound to the specific intent and contract, mitigating replay attacks across contexts.

## Standard Contract Interface (Clarity)

Semantics match ERC-8001 exactly (reverts, events, status transitions); see EIP spec.

## Lifecycle Rules

An implementation of SIP-XXX MUST enforce the following lifecycle:

1. **Proposal:** An initiator calls `propose-intent` to register a new intent on-chain. Initially, its status is `Proposed`. At this point, no acceptances are present. The initiator’s signature on the intent (off-chain) is assumed by virtue of them calling the function (the transaction itself confirms their intent).
2. **Acceptance:** Each participant (including possibly the initiator, if the design requires a separate acceptance from them) calls `accept-intent` with their signature. These can happen in any order. The contract verifies each signature and records it. Participants MAY also provide their acceptance via an off-chain aggregator who then submits them in one transaction, but each acceptance must be individually verifiable on-chain. As acceptances come in, the contract may emit events or simply allow querying of how many acceptances are collected. When the final required acceptance is received, the contract SHOULD update the status to `Ready`.
3. **Execution:** Once an intent is `Ready`, it can be executed. Execution might be triggered by a call to `execute-intent`. In some designs, the same transaction that calls `execute-intent` could also carry out the intended action (e.g., via a payload or by triggering another contract, if the intent’s action is encoded in Clarity). The core contract itself does not mandate how the intent’s action is executed – it only tracks the state. After execution, the status becomes `Executed`. Only one execution is allowed; subsequent calls should be rejected or be no-ops.
4. **Cancellation:** At any time before execution (and before expiry), the initiator can cancel the intent, moving it to `Cancelled`. This halts the process and invalidates any collected signatures for that intent.
5. **Expiration:** If the current time passes the intent’s `expiry` (or any acceptance’s `expiry` if earlier), the intent is considered expired. A contract may implement this by not allowing execution after expiry and marking the status as `Expired` when queried. Expiration does not require an explicit transaction; it’s a state that arises from time passing. However, to be reflected on-chain (for example, if one wants to emit an event or prevent further actions), an explicit check is needed in functions like `accept-intent` and `execute-intent`. Once expired, an intent cannot reach `Ready` if it wasn’t already, and certainly cannot be executed. A new intent would have to be proposed if the parties still wish to proceed.

These rules ensure a coherent flow: intents move forward to execution or terminate via cancellation/expiry, but do not revert backwards in state.

## Backwards Compatibility

This SIP does not alter any existing Stacks consensus rules or contract standards. It is an additive standard. There is no direct predecessor in Stacks that it must remain compatible with (the concept is new to Stacks, though inspired by Ethereum).

One consideration: SIP-018 (Structured Data Signing) should be compatible with this SIP’s approach to ensure wallets and tools can sign the required messages. This proposal assumes SIP-018 or an equivalent is available to provide the signing prefix and domain as needed.

## Security Considerations

**Replay Prevention:** By using initiator-specific nonces for intents and including the contract’s identity in the signed message, this protocol prevents signatures from one context being reused in another:contentReference[oaicite:30]{index=30}. Each initiator’s `nonce` ensures they (and their wallet software) won’t accidentally reuse an intent message, and domain separation (SIP number, contract address, chain id) ensures an intent on Stacks mainnet contract “X” cannot be executed on a testnet or a different contract “Y”.

**Signature Verification and Malleability:** Implementations must use Clarity’s crypto functions correctly to avoid accepting forged signatures. Only acceptances that produce a valid recoverable public key matching the participant’s address should be counted. Low-S requirement (as enforced by most Secp256k1 libraries) should be ensured:contentReference[oaicite:31]{index=31} – if using `secp256k1-verify`, it returns false for high-S signatures, and if using recovery, the contract should reject any signature that does not pass verification. Both 64-byte and 65-byte signatures should be accepted to accommodate different wallet implementations (per EIP-2098 compressed form).

**Timeliness (Expiry):** The expiry mechanism is crucial for safety. Without expiries, an old intent could linger and potentially be executed much later under different conditions, or a participant’s acceptance could be “banked” and used when they no longer intend. By expiring intents, we limit this risk. However, note that the contract cannot automatically remove an expired intent without a transaction; it can only prevent further actions. It is up to clients or a scheduled off-chain service to clean up or notify about expired intents. Parties should choose reasonable expiry times – long enough to gather signatures and execute, but short enough to limit risk exposure.

**Partial Signatures / Equivocation:** The protocol does not stop a malicious participant from signing multiple intents (equivocation) hoping only one gets executed. If a participant does so and two intents both become ready, an executor might waste resources preparing both. This is an application-level concern; modules can add penalties or reputation tracking to discourage such behaviour:contentReference[oaicite:32]{index=32}. The core simply treats each intent separately. It is RECOMMENDED that when this standard is used in economic protocols, there are additional incentives (like slashing or deposits) to align participants’ behaviour.

**Front-Running and MEV:** Because intents in this standard are posted on-chain in a public contract, a malicious observer could potentially see a `Proposed` intent and attempt to front-run the eventual action. However, since the intent can only be executed with all signatures and after a certain time, the window for exploitation is limited. For greater privacy, participants might delay broadcasting their acceptances until execution is imminent, or use a commit-reveal scheme where only hashes of signatures are posted initially. Those techniques are outside SIP-XXX’s scope but can be layered on. In environments with high MEV risk, consider encrypting the payload off-chain and only revealing it at execution time:contentReference[oaicite:33]{index=33}.

## Reference Implementation

Reference implementation: [`contracts/erc-8001.clar`](contracts/erc-8001.clar). Implements core EIP-8001 semantics: sha256/BE32 hashing, strict sorted participants (buff21 lex), nonce/replay prot, expiry checks (intent+per-accept), events, getters. Max 20 parts (decidable). Propose tx-proves (no sig), accepts recover-pubk. No payload exec (modules add). Old ref `docs/SIP-ERC-8001-old-reference.clar` deprecated.
