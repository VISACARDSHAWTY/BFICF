
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

interface IIncidentRegistryCorrelation {
    function incidents(bytes32 incidentId)
        external
        view
        returns (
            bytes32 incidentHash,
            uint8 incidentType,
            uint8 severity,
            uint256 timestamp,
            uint8 state,
            address registeredBy
        );

    function markCorrelated(bytes32 incidentId) external;
}

contract CorrelationDecision {
    enum ConfidenceClass {
        LOW,
        MEDIUM,
        HIGH,
        VERY_HIGH
    }

    struct Correlation {
        bytes32 resultHash;
        bytes32 algorithmVersionHash;
        ConfidenceClass confidence;
        uint256 timestamp;
        address submittedBy;
        bool exists;
    }

    DomainRegistry public immutable domainRegistry;
    IIncidentRegistryCorrelation public immutable incidentRegistry;

    mapping(bytes32 => Correlation) public correlations;

    mapping(bytes32 => address[]) private affectedDomains;

    event CorrelationRecorded(
        bytes32 indexed incidentId,
        bytes32 resultHash,
        ConfidenceClass confidence,
        bytes32 algorithmVersionHash,
        address indexed submittedBy,
        uint256 timestamp
    );

    event AffectedDomainRecorded(
        bytes32 indexed incidentId,
        address indexed affectedDomain
    );

    modifier onlyActiveDomain() {
        require(
            domainRegistry.isActiveDomain(msg.sender),
            "Not an active domain"
        );
        _;
    }

    constructor(
        address _domainRegistry,
        address _incidentRegistry
    ) {
        require(
            _domainRegistry != address(0),
            "Invalid domain registry"
        );
        require(
            _incidentRegistry != address(0),
            "Invalid incident registry"
        );

        domainRegistry = DomainRegistry(_domainRegistry);
        incidentRegistry =
            IIncidentRegistryCorrelation(_incidentRegistry);
    }

    function recordCorrelation(
        bytes32 incidentId,
        bytes32 resultHash,
        ConfidenceClass confidence,
        address[] calldata _affectedDomains,
        bytes32 algorithmVersionHash
    ) external onlyActiveDomain {
        require(incidentId != bytes32(0), "Invalid incident ID");
        require(resultHash != bytes32(0), "Invalid result hash");
        require(
            algorithmVersionHash != bytes32(0),
            "Invalid algorithm version"
        );
        require(
            _affectedDomains.length > 0,
            "No affected domains"
        );
        require(
            !correlations[incidentId].exists,
            "Correlation already recorded"
        );

        (
            ,
            ,
            ,
            uint256 incidentTimestamp,
            uint8 incidentState,

        ) = incidentRegistry.incidents(incidentId);

        require(incidentTimestamp != 0, "Incident not found");
        require(incidentState == 0, "Incident not REGISTERED");

        for (uint256 i = 0; i < _affectedDomains.length; i++) {
            address affected = _affectedDomains[i];

            require(
                affected != address(0),
                "Invalid affected domain"
            );
            require(
                domainRegistry.isActiveDomain(affected),
                "Affected domain not active"
            );

            for (uint256 j = 0; j < i; j++) {
                require(
                    _affectedDomains[j] != affected,
                    "Duplicate affected domain"
                );
            }

            affectedDomains[incidentId].push(affected);

            emit AffectedDomainRecorded(incidentId, affected);
        }

        correlations[incidentId] = Correlation({
            resultHash: resultHash,
            algorithmVersionHash: algorithmVersionHash,
            confidence: confidence,
            timestamp: block.timestamp,
            submittedBy: msg.sender,
            exists: true
        });

        emit CorrelationRecorded(
            incidentId,
            resultHash,
            confidence,
            algorithmVersionHash,
            msg.sender,
            block.timestamp
        );

        // Automatically changes REGISTERED -> CORRELATED.
        incidentRegistry.markCorrelated(incidentId);
    }

    function hasCorrelation(
        bytes32 incidentId
    ) external view returns (bool) {
        return correlations[incidentId].exists;
    }

    function getAffectedDomains(
        bytes32 incidentId
    ) external view returns (address[] memory) {
        return affectedDomains[incidentId];
    }

    function isAffectedDomain(
        bytes32 incidentId,
        address domain
    ) external view returns (bool) {
        address[] storage domains = affectedDomains[incidentId];

        for (uint256 i = 0; i < domains.length; i++) {
            if (domains[i] == domain) {
                return true;
            }
        }

        return false;
    }
}
