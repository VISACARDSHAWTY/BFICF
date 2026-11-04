// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

/**
 * @title GovernanceParams
 * @dev Federation-wide parameters. Values are snapshotted by the consuming contracts
 *      at the start of a vote / correlation so changes never affect in-flight decisions.
 */
contract GovernanceParams {
    DomainRegistry public immutable domainRegistry;

    // Basis points (6000 = 60.00%)
    uint256 public quarantineThreshold = 6000; // theta_q
    uint256 public revokeThreshold = 6000;     // theta_r
    uint256 public patchThreshold = 5000;      // theta_p
    uint256 public quorumBasisPoints = 5000;   // share of eligible voters that must reveal

    // Share of the affected domains that must attest a submitted correlation result
    uint256 public correlationQuorumBps = 5000;

    uint256 public commitWindow = 1 days;
    uint256 public revealWindow = 1 days;

    event ThresholdsUpdated(uint256 q, uint256 r, uint256 p, uint256 quorum);
    event WindowsUpdated(uint256 commitWin, uint256 revealWin);
    event CorrelationQuorumUpdated(uint256 bps);

    constructor(address _domainRegistry) {
        require(_domainRegistry != address(0), "Invalid registry");
        domainRegistry = DomainRegistry(_domainRegistry);
    }

    modifier onlySecAuth() {
        require(domainRegistry.isSecurityAuthority(msg.sender), "Not Security Authority");
        _;
    }

    function updateThresholds(
        uint256 _quarantine,
        uint256 _revoke,
        uint256 _patch,
        uint256 _quorum
    ) external onlySecAuth {
        // Zero is rejected: a zero threshold/quorum would let an outcome win with zero votes.
        require(_quarantine > 0 && _quarantine <= 10000, "Invalid quarantine threshold");
        require(_revoke > 0 && _revoke <= 10000, "Invalid revoke threshold");
        require(_patch > 0 && _patch <= 10000, "Invalid patch threshold");
        require(_quorum > 0 && _quorum <= 10000, "Invalid quorum");

        quarantineThreshold = _quarantine;
        revokeThreshold = _revoke;
        patchThreshold = _patch;
        quorumBasisPoints = _quorum;

        emit ThresholdsUpdated(_quarantine, _revoke, _patch, _quorum);
    }

    function updateWindows(uint256 _commitWin, uint256 _revealWin) external onlySecAuth {
        require(_commitWin > 0 && _revealWin > 0, "Invalid voting windows");
        commitWindow = _commitWin;
        revealWindow = _revealWin;
        emit WindowsUpdated(_commitWin, _revealWin);
    }

    function updateCorrelationQuorum(uint256 bps) external onlySecAuth {
        require(bps > 0 && bps <= 10000, "Invalid correlation quorum");
        correlationQuorumBps = bps;
        emit CorrelationQuorumUpdated(bps);
    }
}
