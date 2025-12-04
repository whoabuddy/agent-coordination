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

ERC-8001 defines a minimal, single-chain primitive for multi-party agent coordination. An initiator posts an intent and each participant provides a verifiable acceptance attestation. Once the required set of acceptances is present and fresh, the intent is executable. The standard specifies typed data, lifecycle, mandatory events, and verification rules compatible with EIP-712, ERC-1271, EIP-2098, and EIP-5267.

This SIP ports ERC-8001 faithfully to Stacks/Clarity: sha256 (native), buff structs/principal-hash160, BE32-packing, tx-sender propose (no sig), secp256k1-recover accepts. Max 20 participants (decidable). Reference `contracts/erc-8001.clar`.

# Motivation

Agents in DeFi/MEV/Web3 Gaming and Agentic Commerce often need to act together without a trusted coordinator. Existing intent standards (e.g., ERC-7521, ERC-7683) define single-initiator flows and do not specify multi-party agreement.

ERC-8001 specifies the smallest on-chain primitive for that gap: an initiator’s EIP-712 intent plus per-participant EIP-712/EIP-1271 acceptances. The intent becomes executable only when the required set of acceptances is present and unexpired. Canonical (sorted-unique) participant lists and standard typed data provide replay safety and wallet compatibility. Privacy, thresholds, bonding, and cross-chain are left to modules.

# Specification

The keywords “MUST”, “SHOULD”, and “MAY” are to be interpreted as described in RFC 2119 and RFC 8174.

## Status Codes

Implementations MUST use the canonical enum:

- `None` (u0): default zero state (intent not found)
- `Proposed` (u1): intent proposed, not all acceptances yet
- `Ready` (u2): all participants have accepted, intent executable
- `Executed` (u3): intent successfully executed
- `Cancelled` (u4): intent explicitly cancelled
- `Expired` (u5): intent expired before execution

## Overview

SIP ports:
- Canonical EIP-712 domain for agent coordination
- Typed data (AgentIntent, CoordinationPayload, AcceptanceAttestation)
- Deterministic hashing rules (sha256/BE32)
- Standard interface IAgentCoordination
- Lifecycle (propose → accept → execute/cancel)
- Error surface and status codes

## EIP-712 Domain (adapted)

{name: "ERC-8001", version: "1", chainId, verifyingContract=sha256("stacks-sip-erc8001-ref-v1")}

DomainSep = sha256(nameH32 || versionH32 || chainIdBE32 || verifH32)

## Primary Types

**AgentIntent**:
- payloadHash (buff32): sha256(CoordinationPayload)
- expiry (uint): unix sec > now at propose
- nonce (uint): > get-agent-nonce(agent)
- agentId (principal): proposer tx-sender
- coordinationType (buff32): e.g. sha256("MEV_SANDWICH_COORD_V1")
- coordinationValue (uint): informational
- participants (list 20 principal): unique ascending hash160; inc agent

**CoordinationPayload** (off-chain; opaque):
- version (buff32)
- coordinationType (buff32; == AgentIntent)
- coordinationData (buff)
- conditionsHash (buff32)
- timestamp (uint)
- metadata (buff)

**AcceptanceAttestation**:
- intentHash (buff32): intentStructHash
- participant (principal): signer tx-sender
- nonce (uint): u0 core
- expiry (uint): >now at accept/execute
- conditionsHash (buff32)
- signature (buff65): secp256k1 recid

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

## Typed Data Hashes

**AGENT_INTENT_TYPEHASH** = sha256("AgentIntent(bytes32 payloadHash,uint64 expiry,uint64 nonce,address agentId,bytes32 coordinationType,uint256 coordinationValue,bytes32 participantsHash)")

**ACCEPTANCE_TYPEHASH** = sha256("AcceptanceAttestation(bytes32 intentHash,address participant,uint64 nonce,uint64 expiry,bytes32 conditionsHash)")

participantsHash = sha256(concat(hash160(p) for p in participants))  ;; sorted unique

intentStructHash = sha256(TYPEHASH || payloadHash || u64BE32(expiry) || u64BE32(nonce) || addr32(agent) || coordType32 || u256BE32(value) || participantsHash)

acceptanceStructHash = sha256(TYPEHASH || intentHash || addr32(participant) || u64BE32(nonce) || u64BE32(expiry) || conditions32)

acceptDigest = sha256(0x1901 || domainSep || acceptanceStructHash)

intentHash = intentStructHash (for acceptance.intentHash)

## Interface

See Standard Contract Interface (above). Matches IAgentCoordination trait.

Events (print tuples) match EIP exactly.

## Semantics

**propose-coordination** MUST revert if:
- expiry ≤ now
- nonce ≤ get-agent-nonce(agent)
- participants not strictly ascending unique (buff21 lex); !contains agent
- intentHash collision

Stores Proposed (accept-count=0); set agent-nonce; emit Proposed.

**accept-coordination** MUST revert if:
- !exists/expired (now > expiry)
- status != PROPOSED
- !participant / already accepted
- accept-expiry ≤ now
- sig invalid (recover principal != tx-sender)

Store acceptance; ++count; READY if full; emit Accepted; return all-accepted?

**execute-coordination** MUST revert if:
- status != READY
- now > expiry
- any accept-expiry < now
- sha256(payload) != payloadHash

Set Executed; emit Executed (success=true, result=0x{}); return (true 0x{}).

**cancel-coordination** MUST revert if:
- !exists
- status EXECUTED/CANCELLED
- !(agent==tx-sender or now>expiry)

Set Cancelled; emit Cancelled.

**get-coordination-status**: None/err if !exists; auto EXPIRED if now>expiry & !EXEC/CANC; return {status,effective,agent,participants,accepted-by,expiry}

Nonces: monotonic per-agent intents; accept nonce=u0 core.

## Errors

Canonical u100+ (ref impl):

| u100 | Unauthorized |
| u101 | NotFound |
| u102 | InvalidState |
| u103 | InvalidSig |
| u104 | NotParticipant |
| u105 | AlreadyAccepted |
| u106 | ExpiredIntent |
| u107 | NonceTooLow |
| u108 | InvalidParticipants |
| u109 | ExpiredAcceptance |
| u110 | PayloadHashMismatch |

# Rationale

Sorted participant lists remove hash malleability and allow off-chain deduplication. Separation of intent and acceptance allows off-chain collation and a single on-chain check. Keeping ERC-8001 single-chain avoids coupling to bridge semantics and keeps the primitive audit-friendly. Wallet friendliness: EIP-712 arrays let signers see actual participant addresses.

# Backwards Compatibility

ERC-8001 introduces a new interface. It is compatible with EOA and contract wallets via ECDSA and ERC-1271. It does not modify existing standards. SIP adds no breaking changes to Stacks.

# Security Considerations

**Replay**: Domain binding + monotonic nonces prevent cross-contract replay.

**Malleability**: secp256k1-recover? handles low-S/65b.

**Equivocation**: Participant may sign conflicts; mitigate w/ modules (slashing/reputation).

**Liveness**: TTL on intent/accepts; executors ensure time buffer.

**MEV**: If coordinationData reveals strategy, use Privacy module (commit-reveal/encryption).

# Copyright

Copyright and related rights waived via CC0.

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
