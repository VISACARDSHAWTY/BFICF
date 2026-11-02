
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

contract IncidentRegistry {
    enum IncidentType {
        SOFTWARE,
        HARDWARE,
        CYBER
    }

    enum IncidentState {
        REGISTERED,
        CORRELATED,
        RESPONSE_PROPOSED,
        VOTING,
        APPROVED,
        EXECUTING,
        VERIFIED,
        CLOSED
    }

    struct Incident {
        bytes32 incidentHash;
        IncidentType incidentType;
        uint8 severity;
        uint256 timestamp;
        IncidentState state;
        address registeredBy;
    }

    mapping(bytes32 => Incident) public incidents;

    DomainRegistry public immutable domainRegistry;

    address public admin;
    address public correlationDecision;
    address public responseProposal;

    event IncidentRegistered(
        bytes32 indexed incidentId,
        address indexed registeredBy,
        IncidentType incidentType,
        uint8 severity,
        uint256 timestamp
    );

    event IncidentStateUpdated(
        bytes32 indexed incidentId,
        IncidentState oldState,
        IncidentState newState
    );

    event WorkflowContractsUpdated(
        address correlationDecision,
        address responseProposal
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyActiveDomain() {
        require(
            domainRegistry.isActiveDomain(msg.sender),
            "Not an active domain"
        );
        _;
    }

    modifier onlyCorrelationDecision() {
        require(
            msg.sender == correlationDecision &&
            correlationDecision != address(0),
            "Not correlation contract"
        );
        _;
    }

    modifier onlyResponseProposal() {
        require(
            msg.sender == responseProposal &&
            responseProposal != address(0),
            "Not response proposal contract"
        );
        _;
    }

    constructor(address _domainRegistry) {
        require(
            _domainRegistry != address(0),
            "Invalid registry address"
        );

        domainRegistry = DomainRegistry(_domainRegistry);
        admin = msg.sender;
    }

    function setWorkflowContracts(
        address _correlationDecision,
        address _responseProposal
    ) external onlyAdmin {
        require(
            _correlationDecision != address(0),
            "Invalid correlation address"
        );
        require(
            _responseProposal != address(0),
            "Invalid proposal address"
        );

        correlationDecision = _correlationDecision;
        responseProposal = _responseProposal;

        emit WorkflowContractsUpdated(
            _correlationDecision,
            _responseProposal
        );
    }

    function registerIncident(
        bytes32 incidentId,
        IncidentType incidentType,
        uint8 severity,
        uint256 timestamp
    ) external onlyActiveDomain {
        require(incidentId != bytes32(0), "Invalid incident ID");
        require(timestamp != 0, "Invalid timestamp");
        require(severity <= 10, "Invalid severity");
        require(
            incidents[incidentId].timestamp == 0,
            "Incident already registered"
        );

        incidents[incidentId] = Incident({
            incidentHash: incidentId,
            incidentType: incidentType,
            severity: severity,
            timestamp: timestamp,
            state: IncidentState.REGISTERED,
            registeredBy: msg.sender
        });

        emit IncidentRegistered(
            incidentId,
            msg.sender,
            incidentType,
            severity,
            timestamp
        );
    }

    // Only CorrelationDecision can perform REGISTERED -> CORRELATED.
    function markCorrelated(
        bytes32 incidentId
    ) external onlyCorrelationDecision {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");
        require(
            incident.state == IncidentState.REGISTERED,
            "Incident not REGISTERED"
        );

        IncidentState oldState = incident.state;
        incident.state = IncidentState.CORRELATED;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            incident.state
        );
    }

    // Only ResponseProposal can perform CORRELATED -> RESPONSE_PROPOSED.
    function markResponseProposed(
        bytes32 incidentId
    ) external onlyResponseProposal {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");
        require(
            incident.state == IncidentState.CORRELATED,
            "Incident not CORRELATED"
        );

        IncidentState oldState = incident.state;
        incident.state = IncidentState.RESPONSE_PROPOSED;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            incident.state
        );
    }

    // Remaining lifecycle transitions are kept sequential.
    // The two transitions above cannot be bypassed manually.
    function advanceState(
        bytes32 incidentId,
        IncidentState newState
    ) external onlyActiveDomain {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");

        IncidentState oldState = incident.state;

        require(
            uint8(newState) == uint8(oldState) + 1,
            "Invalid transition"
        );

        require(
            newState != IncidentState.CORRELATED &&
            newState != IncidentState.RESPONSE_PROPOSED,
            "Use workflow contract"
        );

        incident.state = newState;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            newState
        );
    }
}
