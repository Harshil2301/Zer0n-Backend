// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BountyEscrow
 * @dev Escrow contract for autonomous bug bounty payouts in the ZerOn ecosystem.
 */
contract BountyEscrow {
    address public enterprise;
    address public oracle;
    uint256 public bountyAmount;
    bool public isActive;
    uint8 private unlocked = 1; // Reentrancy Guard state

    event BountyDeposited(address indexed enterprise, uint256 amount);
    event VulnerabilityVerified(address indexed botWallet, string ipfsProofHash, uint256 payout);
    event EscrowCancelled(address indexed enterprise, uint256 refundedAmount);

    modifier nonReentrant() {
        require(unlocked == 1, "ReentrancyGuard: reentrant call");
        unlocked = 0;
        _;
        unlocked = 1;
    }

    modifier onlyOracle() {
        require(msg.sender == oracle, "Unauthorized: Only the ZerOn Oracle can call this");
        _;
    }

    modifier onlyEnterprise() {
        require(msg.sender == enterprise, "Unauthorized: Only the funding enterprise can call this");
        _;
    }

    constructor(address _oracle) {
        enterprise = msg.sender;
        oracle = _oracle;
        isActive = false;
    }

    /**
     * @dev Enterprise funds the escrow contract.
     */
    function depositBounty() external payable onlyEnterprise {
        require(msg.value > 0, "Bounty must be greater than 0");
        bountyAmount += msg.value;
        isActive = true;
        emit BountyDeposited(msg.sender, msg.value);
    }

    /**
     * @dev Oracle triggers the payout upon verifying the IPFS proof.
     * @param _botAddress The Web3 wallet of the bot operator or researcher.
     * @param _ipfsProofHash The CID of the vulnerability PoC pinned to IPFS.
     */
    function releaseBounty(address payable _botAddress, string memory _ipfsProofHash) external onlyOracle nonReentrant {
        require(isActive == true, "Contract is inactive");
        require(address(this).balance > 0, "Insufficient funds in escrow");

        // Calculate payout (in a real scenario this might be tiered based on CVSS)
        // For simplicity, we payout the entire bounty pool to the first successful verifiable submission.
        uint256 payout = address(this).balance;
        
        emit VulnerabilityVerified(_botAddress, _ipfsProofHash, payout);
        
        isActive = false;
        bountyAmount = 0;
        
        (bool success, ) = _botAddress.call{value: payout}("");
        require(success, "Transfer failed");
    }

    /**
     * @dev Emergency withdrawal for enterprise if no bugs are found.
     */
    function cancelEscrow() external onlyEnterprise nonReentrant {
        require(isActive == true, "Contract is not active");
        uint256 amount = address(this).balance;
        isActive = false;
        bountyAmount = 0;
        
        emit EscrowCancelled(msg.sender, amount);
        
        (bool success, ) = payable(enterprise).call{value: amount}("");
        require(success, "Refund failed");
    }
}
