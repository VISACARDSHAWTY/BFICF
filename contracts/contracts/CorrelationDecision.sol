// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

interface IIncidentRegistryCorrelation {
    function incidentExists(bytes32 incidentId) external view returns (bool);
    function stateOf(bytes32 incidentId) external view returns (uint8);
    function markCorrelated(bytes32 incidentId) external;
}

interface IGovernanceParamsCorrelation {
    function correlationQuorumBps() external view returns (uint256);
}

/**
 * @title CorrelationDecision
 * @dev Two-step, attested correlation.
 *
 *  1. The federated-correlation service (CORRELATOR_ROLE) submits the result commitment,
 *     confidence class, algorithm version and the affected domains.
 *  2. Affected domains attest the SAME result hash (after checking it against their own
 *     off-chain view). When attestations reach the governance quorum the result is recorded
 *     and the incident moves REGISTERED -> CORRELATED.
 *
 *  A single (malicious) submitter can therefore no longer fix the correlation result.
 *  The correlator may re-submit while a result is still pending (new round, attestations reset).
 */
contract CorrelationDecision {
    enum ConfidenceClass { LOW, MEDIUM, HIGH, VERY_HIGH }

    struct Correlation {
        bytes32 resultHash;
        bytes32 algorithmVersionHash;
        ConfidenceClass confidence;
        uint256 timestamp;
        address submittedBy;
        bool exists;
    }

    struct Pending {
        bytes32 resultHash;
        bytes32 algorithmVersionHash;
        ConfidenceClass confidence;
        address submittedBy;
        uint256 submittedAt;
        uint256 round;
        uint256 attestations;
        uint256 required;
        bool active;
    }

    uint256 public constant MAX_AFFECTED = 32;

    DomainRegistry public immutable domainRegistry;
    IIncidentRegistryCorrelation public immutable incidentRegistry;
    IGovernanceParamsCorrelation public immutable governanceParams;

    mapping(bytes32 => Correlation) public correlations;
    mapping(bytes32 => Pending) public pending;

    mapping(bytes32 => address[]) private pendingAffected;
    mapping(bytes32 => mapping(address => bool)) private isPendingAffected;
    mapping(bytes32 => mapping(uint256 => mapping(address => bool))) private attested;

    mapping(bytes32 => address[]) private affectedDomains;
    mapping(bytes32 => mapping(address => bool)) private affected;

    event CorrelationSubmitted(
        bytes32 indexed incidentId,
        bytes32 resultHash,
        ConfidenceClass confidence,
        bytes32 algorithmVersionHash,
        address indexed submittedBy,
        uint256 round,
        uint256 required
    );
    event CorrelationAttested(bytes32 indexed incidentId, address indexed domain, uint256 round, uint256 attestations);
    event CorrelationRecorded(
        bytes32 indexed incidentId,
        bytes32 resultHash,
        ConfidenceClass confidence,
        bytes32 algorithmVersionHash,
        address indexed submittedBy,
        uint256 timestamp
    );
    event AffectedDomainRecorded(bytes32 indexed incidentId, address indexed affectedDomain);

    modifier onlyActiveDomain() {
        require(domainRegistry.isActiveDomain(msg.sender), "Not an active domain");
        _;
    }

    modifier onlyCorrelator() {
        require(domainRegistry.isCorrelator(msg.sender), "Not correlator");
        _;
    }

    constructor(address _domainRegistry, address _incidentRegistry, address _governanceParams) {
        require(_domainRegistry != address(0), "Invalid domain registry");
        require(_incidentRegistry != address(0), "Invalid incident registry");
        require(_governanceParams != address(0), "Invalid governance params");

        domainRegistry = DomainRegistry(_domainRegistry);
        incidentRegistry = IIncidentRegistryCorrelation(_incidentRegistry);
        governanceParams = IGovernanceParamsCorrelation(_governanceParams);
    }

    function submitCorrelation(
        bytes32 incidentId,
        bytes32 resultHash,
        ConfidenceClass confidence,
        address[] calldata _affectedDomains,
        bytes32 algorithmVersionHash
    ) external onlyCorrelator {
        require(resultHash != bytes32(0), "Invalid result hash");
        require(algorithmVersionHash != bytes32(0), "Invalid algorithm version");
        require(!correlations[incidentId].exists, "Correlation already recorded");
        require(incidentRegistry.incidentExists(incidentId), "Incident not found");
        require(incidentRegistry.stateOf(incidentId) == 0, "Incident not REGISTERED");

        _setPendingAffected(incidentId, _affectedDomains);

        uint256 required = _requiredAttestations(_affectedDomains.length);
        uint256 round = pending[incidentId].round + 1;

        pending[incidentId] = Pending({
            resultHash: resultHash,
            algorithmVersionHash: algorithmVersionHash,
            confidence: confidence,
            submittedBy: msg.sender,
            submittedAt: block.timestamp,
            round: round,
            attestations: 0,
            required: required,
            active: true
        });

        emit CorrelationSubmitted(
            incidentId, resultHash, confidence, algorithmVersionHash, msg.sender, round, required
        );
    }

    function attestCorrelation(bytes32 incidentId, bytes32 resultHash) external onlyActiveDomain {
        Pending storage p = pending[incidentId];

        require(p.active, "No pending correlation");
        require(p.resultHash == resultHash, "Result hash mismatch");
        require(isPendingAffected[incidentId][msg.sender], "Not an affected domain");
        require(!attested[incidentId][p.round][msg.sender], "Already attested");

        attested[incidentId][p.round][msg.sender] = true;
        p.attestations++;

        emit CorrelationAttested(incidentId, msg.sender, p.round, p.attestations);

        if (p.attestations >= p.required) {
            _finalize(incidentId, p);
        }
    }

    // ------------------------------------------------------------------

    function _setPendingAffected(bytes32 incidentId, address[] calldata list) internal {
        require(list.length > 0, "No affected domains");
        require(list.length <= MAX_AFFECTED, "Too many affected domains");

        address[] storage old = pendingAffected[incidentId];
        for (uint256 i = 0; i < old.length; i++) {
            isPendingAffected[incidentId][old[i]] = false;
        }
        delete pendingAffected[incidentId];

        for (uint256 i = 0; i < list.length; i++) {
            address d = list[i];
            require(d != address(0), "Invalid affected domain");
            require(domainRegistry.isActiveDomain(d), "Affected domain not active");
            require(!isPendingAffected[incidentId][d], "Duplicate affected domain");

            isPendingAffected[incidentId][d] = true;
            pendingAffected[incidentId].push(d);
        }
    }

    function _requiredAttestations(uint256 n) internal view returns (uint256 required) {
        uint256 bps = governanceParams.correlationQuorumBps();
        required = (n * bps + 9999) / 10000; // ceil
        if (required == 0) required = 1;
        if (required > n) required = n;
    }

    function _finalize(bytes32 incidentId, Pending storage p) internal {
        correlations[incidentId] = Correlation({
            resultHash: p.resultHash,
            algorithmVersionHash: p.algorithmVersionHash,
            confidence: p.confidence,
            timestamp: block.timestamp,
            submittedBy: p.submittedBy,
            exists: true
        });
        p.active = false;

        address[] storage list = pendingAffected[incidentId];
        for (uint256 i = 0; i < list.length; i++) {
            affectedDomains[incidentId].push(list[i]);
            affected[incidentId][list[i]] = true;
            emit AffectedDomainRecorded(incidentId, list[i]);
        }

        emit CorrelationRecorded(
            incidentId, p.resultHash, p.confidence, p.algorithmVersionHash, p.submittedBy, block.timestamp
        );

        // REGISTERED -> CORRELATED
        incidentRegistry.markCorrelated(incidentId);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function hasCorrelation(bytes32 incidentId) external view returns (bool) {
        return correlations[incidentId].exists;
    }

    function getConfidence(bytes32 incidentId) external view returns (uint8) {
        require(correlations[incidentId].exists, "Correlation not found");
        return uint8(correlations[incidentId].confidence);
    }

    function getAffectedDomains(bytes32 incidentId) external view returns (address[] memory) {
        return affectedDomains[incidentId];
    }

    function isAffectedDomain(bytes32 incidentId, address domain) external view returns (bool) {
        return affected[incidentId][domain];
    }

    function getPendingAffectedDomains(bytes32 incidentId) external view returns (address[] memory) {
        return pendingAffected[incidentId];
    }
}
