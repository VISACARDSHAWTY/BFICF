// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

interface IIncidentRegistryEvidence {
    function incidentExists(bytes32 incidentId) external view returns (bool);
}

/**
 * @title EvidenceCommitment
 * @dev Commitments H_E = Hash(Evidence) to off-chain evidence, scoped PER INCIDENT.
 *      Keyed by (incidentId, evidenceHash) so nobody can claim a hash under a wrong incident.
 *      ResponseProposal requires at least one commitment before a response can be proposed.
 */
contract EvidenceCommitment {
    struct Commitment {
        bytes32 evidenceHash;
        uint256 timestamp;
        address committedBy;
    }

    DomainRegistry public immutable domainRegistry;
    IIncidentRegistryEvidence public immutable incidentRegistry;

    mapping(bytes32 => mapping(bytes32 => Commitment)) public commitments;
    mapping(bytes32 => uint256) public evidenceCount;

    event EvidenceCommitted(bytes32 indexed incidentId, bytes32 indexed evidenceHash, address committedBy);

    modifier onlyActiveDomain() {
        require(domainRegistry.isActiveDomain(msg.sender), "Not an active domain");
        _;
    }

    constructor(address _domainRegistry, address _incidentRegistry) {
        require(_domainRegistry != address(0), "Invalid registry address");
        require(_incidentRegistry != address(0), "Invalid incident registry");
        domainRegistry = DomainRegistry(_domainRegistry);
        incidentRegistry = IIncidentRegistryEvidence(_incidentRegistry);
    }

    function commitEvidence(bytes32 incidentId, bytes32 evidenceHash) external onlyActiveDomain {
        require(evidenceHash != bytes32(0), "Invalid evidence hash");
        require(incidentRegistry.incidentExists(incidentId), "Incident not found");
        require(commitments[incidentId][evidenceHash].timestamp == 0, "Evidence already committed");

        commitments[incidentId][evidenceHash] = Commitment({
            evidenceHash: evidenceHash,
            timestamp: block.timestamp,
            committedBy: msg.sender
        });
        evidenceCount[incidentId]++;

        emit EvidenceCommitted(incidentId, evidenceHash, msg.sender);
    }

    function incidentHasEvidence(bytes32 incidentId) external view returns (bool) {
        return evidenceCount[incidentId] > 0;
    }

    /// @dev Is this hash committed for this incident?
    function verifyEvidence(bytes32 incidentId, bytes32 claimedEvidenceHash) external view returns (bool) {
        return commitments[incidentId][claimedEvidenceHash].timestamp != 0;
    }

    /// @dev Check Hash(Evidence) == H_E for raw evidence bytes supplied by an authorised party.
    function verifyEvidenceData(bytes32 incidentId, bytes calldata evidence) external view returns (bool) {
        return commitments[incidentId][keccak256(evidence)].timestamp != 0;
    }
}
