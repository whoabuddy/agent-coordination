# ERC-8001 Unit Test Plan

This document outlines a comprehensive test plan for `contracts/erc-8001.clar` using Vitest + Clarinet. Inspired by `aibtc-agent-account` tests:
- **Structure**: `describe("public functions")` / `describe("read-only functions")`.
- **Patterns per function**:
  - Success cases (owner/agent where applicable).
  - Fail unauthorized/not owner.
  - Fail invalid state/contract/config.
  - Agent permission toggles (adapt to nonce/sorted checks).
  - Events/prints match expected payload.
  - Read-only verify state post-change.
- **Coverage**: 100% functions; edge (0/1/20 participants); flows (propose→accept→execute/cancel/expire).
- **Helpers**: Reusable in `tests/erc-8001.test.ts` (extract later).
- **Run**: `npm test` (Vitest TS); `clarinet test` (integration).

## Reusable Helpers (add to tests/erc-8001.test.ts)

```typescript
// Common CVs
const ZERO_32 = bufferCV(new Uint8Array(32));
const FUTURE_EXPIRY = uintCV(2000000000n); // > stacks-block-time
const FUTURE_ACCEPT_EXPIRY = uintCV(2000000001n);
const PAST_EXPIRY = uintCV(1n);
const NONCE_1 = uintCV(1n);
const NONCE_0 = uintCV(0n);
const COORD_VALUE = uintCV(100n);
const CONDITIONS = ZERO_32;

// Accounts
const deployer = accounts.get("deployer")!;
const wallet1 = accounts.get("wallet_1")!;
const wallet2 = accounts.get("wallet_2")!;
const CONTRACT = "erc-8001";

// Sorted participants (buff21 lex order; deployer < wallet1 < wallet2)
const SINGLE_PARTS = listCV([principalCV(deployer)]);
const TWO_PARTS = listCV([principalCV(deployer), principalCV(wallet1)]);
const MANY_PARTS = listCV([principalCV(deployer), principalCV(wallet1), principalCV(wallet2)]); // Add up to 20

// Propose helper (returns intentHash CV | err)
function propose(deployer: Account, participants: ClarityValue, nonce: ClarityValue = NONCE_1) {
  return simnet.callPublicFn(CONTRACT, "propose-coordination", [
    ZERO_32, FUTURE_EXPIRY, nonce, ZERO_32, COORD_VALUE, participants
  ], deployer);
}

// Accept helper (needs sig; mock for now)
function getAcceptSig(intentHash: ClarityValue, participant: Account) {
  // TODO: Compute real EIP-712 digest + secp256k1 sig (use @stacks/transactions or off-chain)
  // Placeholder: Return mock sig65 for success tests
  return bufferCV(new Uint8Array(65)); // Replace with real
}

// Advance time/blocks
function mineToExpiry() {
  simnet.mineEmptyBlocks(100); // Adjust to pass expiry
}
```

## Public Functions: propose-coordination

- [x] Success: nonce=1, sorted unique incl agent → ok(intentHash), nonce→1, req=1
- [x] Fail: nonce=0 → ERR_NONCE_TOO_LOW (107)
- [x] Fail: expiry < now → ERR_EXPIRED (106)
- [x] Fail: agent missing from participants → ERR_INVALID_PARTICIPANTS (108)
- [x] Fail: duplicates → ERR_INVALID_PARTICIPANTS (108)
- [x] Fail: unsorted → ERR_INVALID_PARTICIPANTS (108)
- [ ] Fail: >20 participants → ERR_INVALID_PARTICIPANTS (108)
- [ ] Fail: duplicate intent-hash (re-propose same) → ERR_INVALID_PARTICIPANTS (108)? Or custom err
- [ ] Print: "CoordinationProposed" {intent-hash, proposer, ...}

## Public Functions: accept-coordination

- [ ] Fail: intent not found → ERR_NOT_FOUND (101)
- [ ] Fail: intent expired → ERR_EXPIRED (106)
- [ ] Fail: not PROPOSED → ERR_INVALID_STATE (102)
- [ ] Fail: caller not participant → ERR_NOT_PARTICIPANT (104)
- [ ] Fail: already accepted → ERR_ALREADY_ACCEPTED (105)
- [ ] Fail: accept-expiry < now → ERR_ACCEPT_EXPIRED (109)
- [ ] Fail: invalid sig → ERR_INVALID_SIG (103)
- [ ] Fail: sig recovers wrong principal → ERR_INVALID_SIG (103)
- [ ] Success: single participant → ok(true), status=READY, accept-count=1
- [ ] Success: partial (e.g., 2/3) → ok(false), status=PROPOSED, count=2
- [ ] Success: all N → ok(true), status=READY
- [ ] Print: "CoordinationAccepted" {..., accepted-count, required-count}

## Public Functions: execute-coordination

- [ ] Fail: not found → ERR_NOT_FOUND (101)
- [ ] Fail: not READY → ERR_INVALID_STATE (102)
- [ ] Fail: intent expired → ERR_EXPIRED (106)
- [ ] Fail: any accept expired → ERR_ACCEPT_EXPIRED (109)
- [ ] Fail: sha256(payload) != payload-hash → ERR_PAYLOAD_HASH_MISMATCH (110)
- [ ] Success: valid payload → ok(0x), status=EXECUTED
- [ ] Print: "CoordinationExecuted" {..., success: true}

## Public Functions: cancel-coordination

- [ ] Fail: EXECUTED → ERR_INVALID_STATE (102)
- [ ] Fail: already CANCELLED → ERR_INVALID_STATE (102)
- [ ] Fail: unauthorized (non-agent pre-expiry) → ERR_UNAUTHORIZED (100)
- [ ] Success: agent pre-expiry → ok(true), status=CANCELLED
- [ ] Success: anyone post-expiry → ok(true), status=CANCELLED
- [ ] Print: "CoordinationCancelled" {..., finalStatus: 4}

## Read-only Functions

### get-coordination-status
- [ ] Not found → err ERR_NOT_FOUND
- [ ] PROPOSED: {status:1, ..., accepted-by:[]}
- [ ] READY: {status:2, accepted-by: all}
- [ ] EXECUTED: {status:3}
- [ ] CANCELLED: {status:4}
- [ ] Effective EXPIRED (stored PROPOSED/READY + now > expiry) → status=5
- [ ] accepted-by: correct filtered list (order preserved)

### get-required-acceptances
- [ ] Returns len(participants) or err not found

### get-agent-nonce
- [ ] Initial 0; updates post-propose

### get-eip712-constants
- [ ] Returns full struct (domain, types, etc.)

## Integration Flows

1. **Full success**: propose → all accept → execute → status EXECUTED
2. **Cancel pre-ready**: propose → agent cancel → status CANCELLED
3. **Expire**: propose → mineToExpiry → status EXPIRED (effective)
4. **Partial accept + expire**: propose(3 parts) → 2 accept → expire → fail execute (accept expired)
5. **Re-use nonce fail**: propose nonce1 → propose nonce1 → fail
6. **20 participants**: propose/accept all → execute

## Next Steps
- Implement helpers.
- Add missing `it()` blocks to `tests/erc-8001.test.ts` (prioritize propose/accept).
- Real sigs: Compute digest off-chain, sign w/ secp256k1.
- Events: Parse `print` events (or convert to SIP-019).
- Coverage: `vitest --coverage`.
- Update plan as implemented (checkboxes).
