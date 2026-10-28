// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

/**
 * @title GovernanceParams
 * @dev Stores global federation parameters (voting thresholds, windows, quorum).
 */
contract GovernanceParams {
    DomainRegistry public immutable domainRegistry;

    // Thresholds stored in basis points (e.g. 6000 = 60.00%)
    uint256 public quarantineThreshold = 6000; // theta_q
    uint256 public revokeThreshold = 6000;     // theta_r
    uint256 public patchThreshold = 5000;      // theta_p
    uint256 public quorumBasisPoints = 5000;   // 50.00% quorum

    // Voting and reveal window durations in seconds
    uint256 public commitWindow = 1 days;
    uint256 public revealWindow = 1 days;

    event ThresholdsUpdated(uint256 q, uint256 r, uint256 p, uint256 quorum);
    event WindowsUpdated(uint256 commitWin, uint256 revealWin);

    constructor(address _domainRegistry) {
        require(_domainRegistry != address(0), "Invalid registry");
        domainRegistry = DomainRegistry(_domainRegistry);
    }

    modifier onlySecAuth() {
        require(domainRegistry.hasRole(domainRegistry.SECAUTH_ROLE(), msg.sender), "Not Security Authority");
        _;
    }

    function updateThresholds(
        uint256 _quarantine,
        uint256 _revoke,
        uint256 _patch,
        uint256 _quorum
    ) external onlySecAuth {
        require(_quarantine <= 10000 && _revoke <= 10000 && _patch <= 10000 && _quorum <= 10000, "Invalid basis points");
        quarantineThreshold = _quarantine;
        revokeThreshold = _revoke;
        patchThreshold = _patch;
        quorumBasisPoints = _quorum;

        emit ThresholdsUpdated(_quarantine, _revoke, _patch, _quorum);
    }

    function updateWindows(uint256 _commitWin, uint256 _revealWin) external onlySecAuth {
        commitWindow = _commitWin;
        revealWindow = _revealWin;

        emit WindowsUpdated(_commitWin, _revealWin);
    }
}
