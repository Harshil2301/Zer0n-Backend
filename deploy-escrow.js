const fs = require('fs');
const solc = require('solc');
const { ethers } = require('ethers');
require('dotenv').config();

async function main() {
    console.log("🛠️ Compiling BountyEscrow.sol...");
    
    // Read the contract
    const source = fs.readFileSync('contracts/BountyEscrow.sol', 'utf8');
    
    // Setup solc compiler input
    const input = {
        language: 'Solidity',
        sources: {
            'BountyEscrow.sol': {
                content: source
            }
        },
        settings: {
            outputSelection: {
                '*': {
                    '*': ['*']
                }
            }
        }
    };
    
    // Compile
    const output = JSON.parse(solc.compile(JSON.stringify(input)));
    
    if (output.errors && output.errors.filter(e => e.severity === 'error').length > 0) {
        console.error("Compilation failed:", output.errors);
        return;
    }
    
    const contract = output.contracts['BountyEscrow.sol']['BountyEscrow'];
    const abi = contract.abi;
    const bytecode = contract.evm.bytecode.object;
    
    console.log("✅ Compilation successful!");
    console.log("🌐 Connecting to Avalanche Fuji Testnet...");
    
    // Setup Ethers
    const provider = new ethers.JsonRpcProvider('https://api.avax-test.network/ext/bc/C/rpc');
    const privateKey = process.env.ORACLE_PRIVATE_KEY;
    
    if (!privateKey) {
        console.error("❌ ERROR: No ORACLE_PRIVATE_KEY found in .env");
        return;
    }
    
    const wallet = new ethers.Wallet(privateKey, provider);
    console.log(`🔑 Deploying from Wallet: ${wallet.address}`);
    
    const balance = await provider.getBalance(wallet.address);
    console.log(`💰 Wallet Balance: ${ethers.formatEther(balance)} AVAX`);
    
    if (balance === 0n) {
        console.error("❌ ERROR: Wallet has 0 AVAX. Please fund it using the Avalanche Faucet.");
        return;
    }

    // Deploy
    console.log("🚀 Deploying Smart Contract...");
    const factory = new ethers.ContractFactory(abi, bytecode, wallet);
    
    // The constructor takes the Oracle address. We will set the Oracle to the deploying wallet.
    const deployedContract = await factory.deploy(wallet.address);
    
    console.log("⏳ Waiting for confirmation...");
    await deployedContract.waitForDeployment();
    
    const contractAddress = await deployedContract.getAddress();
    console.log(`\n🎉 SUCCESS! Contract Deployed to Avalanche Fuji!`);
    console.log(`📄 Contract Address: ${contractAddress}`);
    
    // Append the contract address to .env automatically
    fs.appendFileSync('.env', `\n# Deployed Escrow Contract\nESCROW_CONTRACT_ADDRESS=${contractAddress}\n`);
    console.log(`✅ Automatically saved ESCROW_CONTRACT_ADDRESS to .env`);
}

main().catch(console.error);
