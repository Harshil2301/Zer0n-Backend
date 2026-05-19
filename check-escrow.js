const { ethers } = require('ethers');

const PRIVATE_KEY = 'dbf36a3fb45fcbb793324adfc9836fae0a59fb85860ae05615f7ff6722c25dbb';
const CONTRACT_ADDRESS = '0xc43c1c05ed3C8E8f40397302f05322B3A2fe5439';

const abi = [
    "function enterprise() view returns (address)",
    "function oracle() view returns (address)",
    "function isActive() view returns (bool)",
    "function bountyAmount() view returns (uint256)",
    "function depositBounty() payable",
    "function releaseBounty(address payable _botAddress, string memory _ipfsProofHash)"
];

async function main() {
    const provider = new ethers.JsonRpcProvider('https://api.avax-test.network/ext/bc/C/rpc');
    const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
    const contract = new ethers.Contract(CONTRACT_ADDRESS, abi, wallet);
    
    console.log("Checking contract status...");
    
    try {
        const balance = await provider.getBalance(CONTRACT_ADDRESS);
        const isActive = await contract.isActive();
        const enterprise = await contract.enterprise();
        const oracle = await contract.oracle();
        
        console.log(`Contract Balance: ${ethers.formatEther(balance)} AVAX`);
        console.log(`Is Active: ${isActive}`);
        console.log(`Enterprise (Deployer): ${enterprise}`);
        console.log(`Oracle: ${oracle}`);
        console.log(`My Wallet: ${wallet.address}`);
        
        if (wallet.address === enterprise && (!isActive || balance === 0n)) {
            console.log("Funding contract...");
            const tx = await contract.depositBounty({ value: ethers.parseEther("0.01") });
            console.log(`Deposit tx sent: ${tx.hash}`);
            await tx.wait();
            console.log("Deposit confirmed!");
        } else if (wallet.address !== enterprise) {
            console.log("I am not the enterprise, cannot fund it using depositBounty with onlyEnterprise modifier.");
        }
    } catch (e) {
        console.error("Error:", e);
    }
}
main();
