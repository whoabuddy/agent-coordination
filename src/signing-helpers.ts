/**
 * ERC-8001 Agent Coordination - Stacks SIP-018 Signing Helpers
 *
 * This module provides utilities for constructing and signing acceptance
 * attestations compatible with the Stacks agent-coordination contract.
 *
 * Updated for Clarity 4: Uses Unix timestamps for expiry (stacks-block-time)
 *
 * Usage with Hiro Wallet / Leather:
 *   const message = buildAcceptanceMessage(intentHash, participant, expiry, conditions);
 *   const signature = await wallet.signStructuredMessage(message.domain, message.message);
 *   await contract.acceptCoordination(intentHash, expiry, conditions, signature);
 */

import {
    tupleCV,
    stringAsciiCV,
    uintCV,
    bufferCV,
    principalCV,
    serializeCV,
    ClarityValue,
} from '@stacks/transactions';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@stacks/common';

// SIP-018 prefix: ASCII "SIP018"
const SIP018_PREFIX = hexToBytes('534950303138');

// Domain constants (must match contract)
const DOMAIN_NAME = 'ERC-8001-Agent-Coordination';
const DOMAIN_VERSION = '1';

/**
 * Chain IDs for Stacks networks
 */
export const CHAIN_IDS = {
    mainnet: 1,
    testnet: 2147483648, // 0x80000000
} as const;

export type ChainId = typeof CHAIN_IDS[keyof typeof CHAIN_IDS];

/**
 * Build the domain tuple for SIP-018 signing
 */
export function buildDomainTuple(chainId: ChainId): ClarityValue {
    return tupleCV({
        name: stringAsciiCV(DOMAIN_NAME),
        version: stringAsciiCV(DOMAIN_VERSION),
        'chain-id': uintCV(chainId),
    });
}

/**
 * Build an acceptance attestation message for signing
 *
 * @param intentHash - The 32-byte intent hash
 * @param participant - The participant's Stacks principal
 * @param expiry - Unix timestamp for acceptance expiry (Clarity 4)
 * @param conditions - 32-byte conditions hash
 * @param acceptNonce - Always 0 per ERC-8001 spec
 */
export function buildAcceptanceMessage(
    intentHash: Uint8Array | string,
    participant: string,
    expiry: number,
    conditions: Uint8Array | string,
    acceptNonce: number = 0 // Per ERC-8001, always 0
): ClarityValue {
    const hashBytes = typeof intentHash === 'string'
        ? hexToBytes(intentHash.replace('0x', ''))
        : intentHash;
    const condBytes = typeof conditions === 'string'
        ? hexToBytes(conditions.replace('0x', ''))
        : conditions;

    return tupleCV({
        'msg-type': stringAsciiCV('AcceptanceAttestation'),
        'intent-hash': bufferCV(hashBytes),
        participant: principalCV(participant),
        nonce: uintCV(acceptNonce),
        expiry: uintCV(expiry),
        conditions: bufferCV(condBytes),
    });
}

/**
 * Build an agent intent message (for computing intent-hash off-chain)
 *
 * @param payloadHash - sha256 of the execution payload
 * @param expiry - Unix timestamp for intent expiry (Clarity 4)
 * @param nonce - Agent's strictly increasing nonce
 * @param agent - Agent's Stacks principal
 * @param coordinationType - 32-byte type identifier
 * @param coordinationValue - Application-defined value
 * @param participants - Sorted list of participant principals
 */
export function buildIntentMessage(
    payloadHash: Uint8Array | string,
    expiry: number,
    nonce: number,
    agent: string,
    coordinationType: Uint8Array | string,
    coordinationValue: number,
    participants: string[]
): ClarityValue {
    const hashBytes = typeof payloadHash === 'string'
        ? hexToBytes(payloadHash.replace('0x', ''))
        : payloadHash;
    const typeBytes = typeof coordinationType === 'string'
        ? hexToBytes(coordinationType.replace('0x', ''))
        : coordinationType;

    return tupleCV({
        'msg-type': stringAsciiCV('AgentIntent'),
        'payload-hash': bufferCV(hashBytes),
        expiry: uintCV(expiry),
        nonce: uintCV(nonce),
        agent: principalCV(agent),
        'coordination-type': bufferCV(typeBytes),
        'coordination-value': uintCV(coordinationValue),
        // Clarity lists are represented as arrays
        participants: {
            type: 11, // List type
            list: participants.map(p => principalCV(p)),
        } as any,
    });
}

/**
 * Compute SIP-018 structured data hash
 *
 * Formula: sha256(SIP018_PREFIX || sha256(domain) || sha256(message))
 */
export function computeStructuredDataHash(
    domain: ClarityValue,
    message: ClarityValue
): Uint8Array {
    const domainBytes = serializeCV(domain);
    const messageBytes = serializeCV(message);

    const domainHash = sha256(domainBytes);
    const messageHash = sha256(messageBytes);

    const combined = new Uint8Array([
        ...SIP018_PREFIX,
        ...domainHash,
        ...messageHash,
    ]);

    return sha256(combined);
}

/**
 * Compute the digest that a participant should sign for acceptance
 *
 * @param chainId - Network chain ID
 * @param intentHash - The coordination intent hash
 * @param participant - Participant's principal
 * @param expiry - Unix timestamp for acceptance expiry
 * @param conditions - Conditions hash
 */
export function computeAcceptanceDigest(
    chainId: ChainId,
    intentHash: Uint8Array | string,
    participant: string,
    expiry: number,
    conditions: Uint8Array | string
): Uint8Array {
    const domain = buildDomainTuple(chainId);
    const message = buildAcceptanceMessage(
        intentHash,
        participant,
        expiry,
        conditions
    );

    return computeStructuredDataHash(domain, message);
}

/**
 * Compute the intent-hash for a proposed coordination
 */
export function computeIntentHash(
    chainId: ChainId,
    payloadHash: Uint8Array | string,
    expiry: number,
    nonce: number,
    agent: string,
    coordinationType: Uint8Array | string,
    coordinationValue: number,
    participants: string[]
): Uint8Array {
    const domain = buildDomainTuple(chainId);
    const message = buildIntentMessage(
        payloadHash,
        expiry,
        nonce,
        agent,
        coordinationType,
        coordinationValue,
        participants
    );

    return computeStructuredDataHash(domain, message);
}

/**
 * Format for wallet signing via stx_signStructuredMessage
 */
export interface SigningRequest {
    domain: string; // Hex-encoded serialized domain tuple
    message: string; // Hex-encoded serialized message tuple
}

/**
 * Prepare acceptance for wallet signing
 *
 * Returns hex-encoded domain and message for use with:
 * - Hiro Wallet's signStructuredMessage
 * - Leather's stx_signStructuredMessage
 * - Xverse's structured message signing
 *
 * @param chainId - Network chain ID
 * @param intentHash - The coordination intent hash
 * @param participant - Participant's principal
 * @param expiry - Unix timestamp for acceptance expiry
 * @param conditions - Conditions hash
 */
export function prepareAcceptanceForSigning(
    chainId: ChainId,
    intentHash: Uint8Array | string,
    participant: string,
    expiry: number,
    conditions: Uint8Array | string
): SigningRequest {
    const domain = buildDomainTuple(chainId);
    const message = buildAcceptanceMessage(
        intentHash,
        participant,
        expiry,
        conditions
    );

    return {
        domain: bytesToHex(serializeCV(domain)),
        message: bytesToHex(serializeCV(message)),
    };
}

/**
 * Helper: Create a 32-byte coordination type from a string
 */
export function createCoordinationType(typeStr: string): Uint8Array {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(typeStr);
    const result = new Uint8Array(32);
    result.set(bytes.slice(0, 32));
    return result;
}

/**
 * Helper: Create a 32-byte conditions hash (sha256 of conditions data)
 */
export function createConditionsHash(conditions: any): Uint8Array {
    const json = JSON.stringify(conditions);
    const encoder = new TextEncoder();
    return sha256(encoder.encode(json));
}

/**
 * Helper: Sort principals for participant list
 *
 * ERC-8001 requires participants to be sorted lexicographically by their
 * consensus serialization. This ensures deterministic intent-hash computation.
 */
export function sortParticipants(participants: string[]): string[] {
    return [...participants].sort((a, b) => {
        const aBytes = serializeCV(principalCV(a));
        const bBytes = serializeCV(principalCV(b));

        for (let i = 0; i < Math.min(aBytes.length, bBytes.length); i++) {
            if (aBytes[i] !== bBytes[i]) {
                return aBytes[i] - bBytes[i];
            }
        }
        return aBytes.length - bBytes.length;
    });
}

/**
 * Helper: Get current Unix timestamp (for setting expiry)
 */
export function getCurrentTimestamp(): number {
    return Math.floor(Date.now() / 1000);
}

/**
 * Helper: Calculate expiry timestamp from duration
 *
 * @param durationSeconds - Duration in seconds
 * @returns Unix timestamp for expiry
 */
export function getExpiryFromDuration(durationSeconds: number): number {
    return getCurrentTimestamp() + durationSeconds;
}

// Common durations in seconds
export const DURATIONS = {
    ONE_HOUR: 3600,
    ONE_DAY: 86400,
    ONE_WEEK: 604800,
    ONE_MONTH: 2592000,
} as const;

// ============================================================================
// Example Usage (Clarity 4 with Unix timestamps)
// ============================================================================

/*
import {
  prepareAcceptanceForSigning,
  computeIntentHash,
  sortParticipants,
  createCoordinationType,
  getExpiryFromDuration,
  CHAIN_IDS,
  DURATIONS
} from './signing-helpers';

// 1. Agent proposes coordination with Unix timestamp expiry
const participants = sortParticipants([
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM', // agent
  'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG', // participant 2
]);

const payloadHash = sha256(new TextEncoder().encode('execute-action'));
const coordinationType = createCoordinationType('multi-sig-transfer');

// Expiry in 1 day (Unix timestamp)
const expiry = getExpiryFromDuration(DURATIONS.ONE_DAY);

const intentHash = computeIntentHash(
  CHAIN_IDS.testnet,
  payloadHash,
  expiry,
  1, // nonce
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM', // agent
  coordinationType,
  2, // coordination value (e.g., required signatures)
  participants
);

// 2. Participant prepares to sign acceptance
const acceptanceExpiry = getExpiryFromDuration(DURATIONS.ONE_HOUR);

const signingRequest = prepareAcceptanceForSigning(
  CHAIN_IDS.testnet,
  intentHash,
  'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG', // participant
  acceptanceExpiry,
  new Uint8Array(32) // empty conditions
);

// 3. Sign with wallet (browser extension)
const signature = await window.LeatherProvider.request({
  method: 'stx_signStructuredMessage',
  params: {
    domain: signingRequest.domain,
    message: signingRequest.message,
  }
});

// 4. Submit acceptance to contract
await contractCall({
  contractAddress: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
  contractName: 'agent-coordination-v2',
  functionName: 'accept-coordination',
  functionArgs: [
    bufferCV(intentHash),
    uintCV(acceptanceExpiry),
    bufferCV(new Uint8Array(32)), // conditions
    bufferCV(signature.signature),
  ],
});
*/
