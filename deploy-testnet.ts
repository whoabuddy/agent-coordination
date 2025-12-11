/**
 * ERC-8001 Testnet Deployment Script
 *
 * Prerequisites:
 * 1. Get testnet STX from faucet: https://explorer.hiro.so/sandbox/faucet?chain=testnet
 * 2. Set your private key in .env or pass as argument
 *
 * Usage:
 *   npx ts-node deploy-testnet.ts
 *   # or
 *   DEPLOYER_KEY=your_private_key npx ts-node deploy-testnet.ts
 */

import {
    makeContractDeploy,
    broadcastTransaction,
    AnchorMode,
    PostConditionMode,
    getAddressFromPrivateKey,
    TransactionVersion,
    ClarityVersion,
} from "@stacks/transactions";
import { StacksTestnet } from "@stacks/network";
import * as fs from "fs";
import * as path from "path";

// Configuration
const CONFIG = {
    contractName: "erc-8001",
    contractPath: "./contracts/erc-8001.clar",
    network: new StacksTestnet(),
    clarityVersion: ClarityVersion.Clarity3,
    fee: 50000, // 0.05 STX - adjust if needed
};

async function getAccountNonce(address: string): Promise<number> {
    const url = `https://api.testnet.hiro.so/extended/v1/address/${address}/nonces`;
    const response = await fetch(url);
    const data = await response.json();
    return data.possible_next_nonce;
}

async function waitForTransaction(txId: string, maxAttempts = 60): Promise<any> {
    const url = `https://api.testnet.hiro.so/extended/v1/tx/${txId}`;

    for (let i = 0; i < maxAttempts; i++) {
        const response = await fetch(url);
        const data = await response.json();

        if (data.tx_status === "success") {
            return { success: true, data };
        } else if (data.tx_status === "abort_by_response" || data.tx_status === "abort_by_post_condition") {
            return { success: false, data, error: data.tx_result?.repr || "Transaction aborted" };
        } else if (data.tx_status === "pending") {
            console.log(`  Pending... (attempt ${i + 1}/${maxAttempts})`);
            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10s
        } else if (data.error) {
            // Transaction not found yet
            console.log(`   Waiting for mempool... (attempt ${i + 1}/${maxAttempts})`);
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }

    return { success: false, error: "Timeout waiting for transaction" };
}

async function deploy() {
    console.log(" ERC-8001 Testnet Deployment\n");

    // Get private key
    const privateKey = process.env.DEPLOYER_KEY;
    if (!privateKey) {
        console.error(" Error: DEPLOYER_KEY environment variable not set");
        console.log("\nUsage:");
        console.log("  DEPLOYER_KEY=your_private_key npx ts-node deploy-testnet.ts");
        console.log("\nGet testnet STX from: https://explorer.hiro.so/sandbox/faucet?chain=testnet");
        process.exit(1);
    }

    // Derive address from private key
    const deployerAddress = getAddressFromPrivateKey(privateKey, TransactionVersion.Testnet);
    console.log(` Deployer: ${deployerAddress}`);

    // Check balance
    const balanceUrl = `https://api.testnet.hiro.so/extended/v1/address/${deployerAddress}/stx`;
    const balanceResponse = await fetch(balanceUrl);
    const balanceData = await balanceResponse.json();
    const balance = BigInt(balanceData.balance);
    console.log(` Balance: ${Number(balance) / 1_000_000} STX`);

    if (balance < BigInt(CONFIG.fee)) {
        console.error(` Insufficient balance. Need at least ${CONFIG.fee / 1_000_000} STX`);
        console.log("Get testnet STX from: https://explorer.hiro.so/sandbox/faucet?chain=testnet");
        process.exit(1);
    }

    // Read contract source
    const contractPath = path.resolve(CONFIG.contractPath);
    if (!fs.existsSync(contractPath)) {
        console.error(` Contract file not found: ${contractPath}`);
        process.exit(1);
    }

    const contractSource = fs.readFileSync(contractPath, "utf-8");
    console.log(` Contract: ${CONFIG.contractName} (${contractSource.length} bytes)`);

    // Get nonce
    const nonce = await getAccountNonce(deployerAddress);
    console.log(` Nonce: ${nonce}`);

    // Build deployment transaction
    console.log("\n Building transaction...");
    const txOptions = {
        contractName: CONFIG.contractName,
        codeBody: contractSource,
        clarityVersion: CONFIG.clarityVersion,
        senderKey: privateKey,
        network: CONFIG.network,
        anchorMode: AnchorMode.Any,
        postConditionMode: PostConditionMode.Allow,
        fee: CONFIG.fee,
        nonce: nonce,
    };

    const transaction = await makeContractDeploy(txOptions);

    // Broadcast
    console.log(" Broadcasting to testnet...");
    const broadcastResult = await broadcastTransaction(transaction, CONFIG.network);

    if ("error" in broadcastResult) {
        console.error(" Broadcast failed:", broadcastResult.error);
        if (broadcastResult.reason) {
            console.error("   Reason:", broadcastResult.reason);
        }
        process.exit(1);
    }

    const txId = broadcastResult.txid;
    console.log(`\n Transaction broadcast!`);
    console.log(`   TX ID: ${txId}`);
    console.log(`   Explorer: https://explorer.hiro.so/txid/${txId}?chain=testnet`);

    // Wait for confirmation
    console.log("\n Waiting for confirmation...");
    const result = await waitForTransaction(txId);

    if (result.success) {
        console.log("\n Deployment successful!");
        console.log(`   Contract: ${deployerAddress}.${CONFIG.contractName}`);
        console.log(`   Explorer: https://explorer.hiro.so/txid/${txId}?chain=testnet`);
        console.log(`\n Contract Address (copy this):`);
        console.log(`   ${deployerAddress}.${CONFIG.contractName}`);
    } else {
        console.error("\n Deployment failed:", result.error);
        if (result.data) {
            console.error("   Details:", JSON.stringify(result.data.tx_result, null, 2));
        }
        process.exit(1);
    }
}

// Run deployment
deploy().catch(err => {
    console.error(" Unexpected error:", err);
    process.exit(1);
});