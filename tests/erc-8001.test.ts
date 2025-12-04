
import { describe, expect, it } from "vitest";

import {
  principalCV,
  uintCV,
  bufferCV,
  listCV,
} from '@stacks/transactions';

const accounts = simnet.getAccounts();

/*
  The test below is an example. To learn more, read the testing documentation here:
  https://docs.hiro.so/stacks/clarinet-js-sdk
*/

describe("ERC-8001 tests", () => {
  it("ensures simnet is well initialised", () => {
    expect(simnet.blockHeight).toBeDefined();
  });

  it("gets initial agent nonce as 0 for deployer", () => {
    const deployer = accounts.get("deployer")!;
    const { result } = simnet.callReadOnlyFn(
      "erc-8001",
      "get-agent-nonce",
      [principalCV(deployer)],
      deployer
    );
    expect(result).toBeUint(0n);
  });

  it("fails to propose coordination with nonce 0 (ERR_NONCE_TOO_LOW)", () => {
    const deployer = accounts.get("deployer")!;
    const zero32 = bufferCV(new Uint8Array(32));
    const futureExpiry = uintCV(2000000000n);
    const nonce0 = uintCV(0n);
    const coordType = zero32;
    const coordValue = uintCV(100n);
    const participants = listCV([principalCV(deployer)]);
    const { result } = simnet.callPublicFn(
      "erc-8001",
      "propose-coordination",
      [zero32, futureExpiry, nonce0, coordType, coordValue, participants],
      deployer
    );
    expect(result).toBeErr(107n);
  });

  it("proposes coordination successfully with nonce 1", () => {
    const deployer = accounts.get("deployer")!;
    const zero32 = bufferCV(new Uint8Array(32));
    const futureExpiry = uintCV(2000000000n);
    const nonce1 = uintCV(1n);
    const coordType = zero32;
    const coordValue = uintCV(100n);
    const participants = listCV([principalCV(deployer)]);
    const { result: proposeResult } = simnet.callPublicFn(
      "erc-8001",
      "propose-coordination",
      [zero32, futureExpiry, nonce1, coordType, coordValue, participants],
      deployer
    );
    expect(proposeResult).toBeOk();

    const intentHashCV = proposeResult.value!;

    const { result: reqResult } = simnet.callReadOnlyFn(
      "erc-8001",
      "get-required-acceptances",
      [intentHashCV],
      deployer
    );
    expect(reqResult).toBeOk();
    expect(reqResult.value!).toBeUint(1n);

    const { result: nonceResult } = simnet.callReadOnlyFn(
      "erc-8001",
      "get-agent-nonce",
      [principalCV(deployer)],
      deployer
    );
    expect(nonceResult).toBeUint(1n);
  });
});
