// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./DomainRegistry.sol";

/**
 * @title EvidenceCommitment
 * @dev Stores cryptographic commitments to evidence generated during incident analysis.
 */
contract EvidenceCommitment is AccessControl {
    bytes32 public constant DOMAIN_ROLE = keccak256("DOMAIN_ROLE");

    struct EvidenceCommitment {
        bytes32 incidentId;
        bytes32 evidenceHash;
        uint256 timestamp;
        address committedBy;
    }

    // Mapping from evidence hash to commitment data
    mapping(bytes32 => EvidenceCommitment) public commitments;

    // Track which incidents have evidence committed
    mapping(bytes32 => bool) public incidentHasEvidence;

    event EvidenceCommitted(bytes32 indexed incidentId, bytes32 indexed evidenceHash, address committedBy);
    event EvidenceVerified(bytes32 indexed incidentId, bytes32 indexed evidenceHash, bool valid);

    constructor(address _domainRegistry) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Commit evidence for an incident. Only active domains can commit.
     */
    function commitEvidence(bytes32 incidentId, bytes32 evidenceHash) external onlyRole(DOMAIN_ROLE) {
        require(evidenceHash != bytes32(0), "Invalid evidence hash");

        commitments[evidenceHash] = EvidenceCommitment({
            incidentId: incidentId,
            evidenceHash: evidenceHash,
            timestamp: block.timestamp,
            committedBy: msg.sender
        });

        incidentHasEvidence[incidentId] = true;

        emit EvidenceCommitted(incidentId, evidenceHash, msg.sender);
    }

    /**
     * @dev Verify that a claimed evidence hash matches the committed hash.
     */
    function verifyEvidence(bytes32 incidentId, bytes32 claimedEvidenceHash) external view returns (bool) {
        return commitments[claimedEvidenceHash].incidentId == incidentId;
    }
}