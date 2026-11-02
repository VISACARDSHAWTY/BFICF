
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

/**
 * @title EvidenceCommitment
 * @dev Stores cryptographic commitments to incident evidence.
 */
contract EvidenceCommitment {

    struct EvidenceCommitment {
        bytes32 incidentId;
        bytes32 evidenceHash;
        uint256 timestamp;
        address committedBy;
    }

    mapping(bytes32 => EvidenceCommitment) public commitments;

    mapping(bytes32 => bool) public incidentHasEvidence;

    DomainRegistry public immutable domainRegistry;

    event EvidenceCommitted(
        bytes32 indexed incidentId,
        bytes32 indexed evidenceHash,
        address committedBy
    );

    event EvidenceVerified(
        bytes32 indexed incidentId,
        bytes32 indexed evidenceHash,
        bool valid
    );

    modifier onlyActiveDomain() {
        require(
            domainRegistry.isActiveDomain(msg.sender),
            "Not an active domain"
        );
        _;
    }

    constructor(address _domainRegistry) {
        require(_domainRegistry != address(0), "Invalid registry address");

        domainRegistry = DomainRegistry(_domainRegistry);
    }

    /**
     * @dev Commit evidence. Only active domains can commit.
     */
    function commitEvidence(
        bytes32 incidentId,
        bytes32 evidenceHash
    ) external onlyActiveDomain {

        require(
            evidenceHash != bytes32(0),
            "Invalid evidence hash"
        );

        require(
            commitments[evidenceHash].timestamp == 0,
            "Evidence already committed"
        );

        commitments[evidenceHash] = EvidenceCommitment({
            incidentId: incidentId,
            evidenceHash: evidenceHash,
            timestamp: block.timestamp,
            committedBy: msg.sender
        });

        incidentHasEvidence[incidentId] = true;

        emit EvidenceCommitted(
            incidentId,
            evidenceHash,
            msg.sender
        );
    }

    /**
     * @dev Verify whether an evidence hash matches an incident.
     */
    function verifyEvidence(
        bytes32 incidentId,
        bytes32 claimedEvidenceHash
    ) external view returns (bool) {

        return (
            commitments[claimedEvidenceHash].timestamp != 0 &&
            commitments[claimedEvidenceHash].incidentId == incidentId
        );
    }
}
