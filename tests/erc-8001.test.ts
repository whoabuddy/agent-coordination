
import { describe, expect, it } from "vitest";

import {
  principalCV,
  uintCV,
  bufferCV,
  listCV,
  stringAsciiCV,
  ClarityType,
} from '@stacks/transactions';

import type {
  ClarityTupleData,
  ClarityValue,
  ListCV,
  UIntCV,
  BufferCV,
  CallReceipt,
  ReadOnlyFnResult,
} from '@stacks/transactions';

const accounts = simnet.getAccounts();

const CONTRACT = "erc-8001";

const deployer = accounts.get("deployer")!;
const wallet1 = accounts.get("wallet_1")!;
const wallet2 = accounts.get("wallet_2")!;
const wallet3 = accounts.get("wallet_3")!;

const ZERO_32 = bufferCV(new Uint8Array(32));
const FUTURE_EXPIRY = uintCV(2000000000n);
const NONCE_1 = uintCV(1n);
const NONCE_0 = uintCV(0n);
const COORD_VALUE = uintCV(100n);
const PAST_EXPIRY = uintCV(1n);
const FUTURE_ACCEPT_EXPIRY = uintCV(2000000001n);
const CONDITIONS = ZERO_32;

/*
  The test below is an example. To learn more, read the testing documentation here:
  https://docs.hiro.so/stacks/clarinet-js-sdk
*/
const SINGLE_PARTICIPANTS = listCV([principalCV(deployer)]);
const TWO_PARTICIPANTS = listCV([principalCV(deployer), principalCV(wallet1)]);

function propose(
  caller: Account,
  participants: ClarityValue,
  nonce: ClarityValue = NONCE_1
): CallReceipt {
  return simnet.callPublicFn(
    CONTRACT,
    "propose-coordination",
    [
      ZERO_32,
      FUTURE_EXPIRY,
      nonce,
      ZERO_32,
      COORD_VALUE,
      participants,
    ],
    caller
  );
}

function expectProposeEvent(receipt: CallReceipt) {
  expect(receipt.events).toHaveLength(1);
  expect(receipt.events[0]!.type).toBe("contract_event");
  const notificationTuple = receipt.events[0]!.event.value.data as ClarityTupleData;
  const notificationCV = notificationTuple.notification as BufferCV;
  const expectedNotification = new TextEncoder().encode("erc-8001/coordination-proposed");
  expect(notificationCV.value).toEqual(expectedNotification);
}

function getStatusTuple(
  statusResult: ReadOnlyFnResult<ClarityValue>
): ClarityTupleData {
  if (statusResult.result.type !== ClarityType.ResponseOk) {
    throw new Error(`Expected ok, got ${statusResult.result.type}`);
  }
  return statusResult.result.value!.data as ClarityTupleData;
}

function expectStatusProposed(statusTuple: ClarityTupleData, expectedExpiry: UIntCV) {
  expect((statusTuple.status as UIntCV).value).toBe(1n);
  expect((statusTuple.agent as any).toStringCV()).toBe(deployer);
  expect((statusTuple['accepted-by'] as ListCV).list.length).toBe(0);
  expect(statusTuple.expiry as UIntCV).toEqualCV(expectedExpiry);
}

describe(`public functions: ${CONTRACT}`, () => {
  it("ensures simnet is well initialised", () => {
    expect(simnet.blockHeight).toBeDefined();
  });

describe(`read-only functions: ${CONTRACT}`, () => {
  it("get-agent-nonce returns 0 initially", () => {
    const result = simnet.callReadOnlyFn(
      CONTRACT,
      "get-agent-nonce",
      [principalCV(deployer)],
      deployer
    );
    expect(result.result).toBeUint(0n);
  });

  it("get-eip712-constants returns the correct constants", () => {
    const result = simnet.callReadOnlyFn(
      CONTRACT,
      "get-eip712-constants",
      [],
      deployer
    );
    expect(result.result).toBeOk();
    // Further detailed checks can be added by parsing the tuple
  });

  it("get-required-acceptances fails for non-existent intent", () => {
    const badHash = bufferCV(new Uint8Array(32).fill(255));
    const result = simnet.callReadOnlyFn(
      CONTRACT,
      "get-required-acceptances",
      [badHash],
      deployer
    );
    expect(result.result).toBeErr(101n);
  });

  it("get-coordination-status returns PROPOSED after propose", () => {
    // arrange
    const proposeReceipt = propose(deployer, SINGLE_PARTICIPANTS);
    expect(proposeReceipt.result).toBeOk();
    const intentHash = proposeReceipt.result.value as BufferCV;

    // act
    const statusResult = simnet.callReadOnlyFn(
      CONTRACT,
      "get-coordination-status",
      [intentHash],
      deployer
    );

    // assert
    const statusTuple = getStatusTuple(statusResult);
    expectStatusProposed(statusTuple, FUTURE_EXPIRY);
  });

  it("get-coordination-status fails for not found (ERR_NOT_FOUND)", () => {
    const badHash = bufferCV(new Uint8Array(32).fill(255));
    const result = simnet.callReadOnlyFn(
      CONTRACT,
      "get-coordination-status",
      [badHash],
      deployer
    );
    expect(result.result).toBeErr(101n);
  });
});

  it("fails to propose coordination with nonce 0 (ERR_NONCE_TOO_LOW)", () => {
    const receipt = propose(deployer, SINGLE_PARTICIPANTS, NONCE_0);
    expect(receipt.result).toBeErr(107n);
  });

  it("proposes coordination successfully with nonce 1", () => {
    const receipt = propose(deployer, SINGLE_PARTICIPANTS);
    expect(receipt.result).toBeOk();
    expectProposeEvent(receipt);

    const intentHashCV = receipt.result.value as BufferCV;

    const reqResult = simnet.callReadOnlyFn(
      CONTRACT,
      "get-required-acceptances",
      [intentHashCV],
      deployer
    );
    expect(reqResult.result).toBeOk();
    expect(reqResult.result.value!).toBeUint(1n);

    const nonceResult = simnet.callReadOnlyFn(
      CONTRACT,
      "get-agent-nonce",
      [principalCV(deployer)],
      deployer
    );
    expect(nonceResult.result).toBeUint(1n);
  });

  it("fails to propose coordination with past expiry (ERR_EXPIRED)", () => {
    const pastExpiry = uintCV(1n);
    const receipt = simnet.callPublicFn(
      CONTRACT,
      "propose-coordination",
      [
        ZERO_32,
        pastExpiry,
        NONCE_1,
        ZERO_32,
        COORD_VALUE,
        SINGLE_PARTICIPANTS,
      ],
      deployer
    );
    expect(receipt.result).toBeErr(106n);
  });

  it("fails to propose coordination missing agent in participants (ERR_INVALID_PARTICIPANTS)", () => {
    const noAgentParts = listCV([principalCV(wallet1)]);
    const receipt = propose(deployer, noAgentParts);
    expect(receipt.result).toBeErr(108n);
  });

  it("fails to propose coordination with duplicate participants (ERR_INVALID_PARTICIPANTS)", () => {
    const dupParts = listCV([principalCV(deployer), principalCV(deployer)]);
    const receipt = propose(deployer, dupParts);
    expect(receipt.result).toBeErr(108n);
  });

  it("fails to propose coordination with unsorted participants (ERR_INVALID_PARTICIPANTS)", () => {
    const unsortedParts = listCV([principalCV(wallet1), principalCV(deployer)]);
    const receipt = propose(deployer, unsortedParts);
    expect(receipt.result).toBeErr(108n);
  });

  it("fails to propose coordination with >20 participants (ERR_INVALID_PARTICIPANTS)", () => {
    const participants21 = listCV(Array(21).fill(principalCV(deployer)));
    const receipt = propose(deployer, participants21);
    expect(receipt.result).toBeErr(108n);
  });

  it("cancel-coordination() succeeds for agent pre-expiry", () => {
    // arrange
    const receiptPropose = propose(deployer, SINGLE_PARTICIPANTS);
    expect(receiptPropose.result).toBeOk();
    const intentHash = receiptPropose.result.value as BufferCV;

    // act
    const reason = stringAsciiCV("test reason");
    const receiptCancel = simnet.callPublicFn(
      CONTRACT,
      "cancel-coordination",
      [intentHash, reason],
      deployer
    );

    // assert
    expect(receiptCancel.result).toBeOk();

    const statusResult = simnet.callReadOnlyFn(
      CONTRACT,
      "get-coordination-status",
      [intentHash],
      deployer
    );
    const statusTuple = getStatusTuple(statusResult);
    expect((statusTuple.status as UIntCV).value).toBe(4n); // CANCELLED
  });

  it("cancel-coordination() fails for unauthorized caller pre-expiry", () => {
    // arrange
    const receiptPropose = propose(deployer, SINGLE_PARTICIPANTS);
    expect(receiptPropose.result).toBeOk();
    const intentHash = receiptPropose.result.value as BufferCV;

    // act & assert
    const reason = stringAsciiCV("test");
    const receiptCancel = simnet.callPublicFn(
      CONTRACT,
      "cancel-coordination",
      [intentHash, reason],
      wallet3
    );
    expect(receiptCancel.result).toBeErr(100n);
  });

  it("cancel-coordination() fails if already CANCELLED (ERR_INVALID_STATE)", () => {
    // arrange
    const receiptPropose = propose(deployer, SINGLE_PARTICIPANTS);
    expect(receiptPropose.result).toBeOk();
    const intentHash = receiptPropose.result.value as BufferCV;

    const reason = stringAsciiCV("test");
    simnet.callPublicFn(CONTRACT, "cancel-coordination", [intentHash, reason], deployer);

    // act
    const receiptCancel2 = simnet.callPublicFn(
      CONTRACT,
      "cancel-coordination",
      [intentHash, reason],
      deployer
    );

    // assert
    expect(receiptCancel2.result).toBeErr(102n);
  });

  it("accept-coordination() fails if intent not found (ERR_NOT_FOUND)", () => {
    const badHash = bufferCV(new Uint8Array(32).fill(255));
    const dummySig = bufferCV(new Uint8Array(65));
    const receipt = simnet.callPublicFn(
      CONTRACT,
      "accept-coordination",
      [badHash, FUTURE_ACCEPT_EXPIRY, CONDITIONS, dummySig],
      deployer
    );
    expect(receipt.result).toBeErr(101n);
  });

  it("accept-coordination() fails if caller not participant (ERR_NOT_PARTICIPANT)", () => {
    // arrange: propose with single participant (deployer only)
    const receiptPropose = propose(deployer, SINGLE_PARTICIPANTS);
    expect(receiptPropose.result).toBeOk();
    const intentHash = receiptPropose.result.value as BufferCV;

    // act: wallet1 tries to accept (not participant)
    const dummySig = bufferCV(new Uint8Array(65));
    const receipt = simnet.callPublicFn(
      CONTRACT,
      "accept-coordination",
      [intentHash, FUTURE_ACCEPT_EXPIRY, CONDITIONS, dummySig],
      wallet1
    );
    expect(receipt.result).toBeErr(104n);
  });

  it("accept-coordination() fails if accept-expiry expired (ERR_ACCEPT_EXPIRED)", () => {
    // arrange: propose
    const receiptPropose = propose(deployer, SINGLE_PARTICIPANTS);
    expect(receiptPropose.result).toBeOk();
    const intentHash = receiptPropose.result.value as BufferCV;

    // act: accept with past expiry
    const dummySig = bufferCV(new Uint8Array(65));
    const receipt = simnet.callPublicFn(
      CONTRACT,
      "accept-coordination",
      [intentHash, PAST_EXPIRY, CONDITIONS, dummySig],
      deployer
    );
    expect(receipt.result).toBeErr(109n);
  });
});
});
