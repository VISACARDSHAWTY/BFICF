
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
    address public federatedVoting;
    address public responseDecision;
    address public coordinatedResponseExecution;
    address public executionVerification;

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

    event GovernanceContractsUpdated(
        address federatedVoting,
        address responseDecision
    );

    event ExecutionContractsUpdated(
        address coordinatedResponseExecution,
        address executionVerification
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

    modifier onlyFederatedVoting() {
        require(
            msg.sender == federatedVoting &&
            federatedVoting != address(0),
            "Not voting contract"
        );
        _;
    }

    modifier onlyResponseDecision() {
        require(
            msg.sender == responseDecision &&
            responseDecision != address(0),
            "Not decision contract"
        );
        _;
    }

    modifier onlyExecutionContract() {
        require(
            msg.sender == coordinatedResponseExecution &&
            coordinatedResponseExecution != address(0),
            "Not execution contract"
        );
        _;
    }

    modifier onlyVerificationContract() {
        require(
            msg.sender == executionVerification &&
            executionVerification != address(0),
            "Not verification contract"
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

    function setGovernanceContracts(
        address _federatedVoting,
        address _responseDecision
    ) external onlyAdmin {
        require(
            _federatedVoting != address(0),
            "Invalid voting address"
        );
        require(
            _responseDecision != address(0),
            "Invalid decision address"
        );

        federatedVoting = _federatedVoting;
        responseDecision = _responseDecision;

        emit GovernanceContractsUpdated(
            _federatedVoting,
            _responseDecision
        );
    }

    function setExecutionContracts(
        address _coordinatedResponseExecution,
        address _executionVerification
    ) external onlyAdmin {
        require(
            _coordinatedResponseExecution != address(0),
            "Invalid execution address"
        );
        require(
            _executionVerification != address(0),
            "Invalid verification address"
        );

        coordinatedResponseExecution =
            _coordinatedResponseExecution;

        executionVerification = _executionVerification;

        emit ExecutionContractsUpdated(
            _coordinatedResponseExecution,
            _executionVerification
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

    // REGISTERED -> CORRELATED
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

    // CORRELATED -> RESPONSE_PROPOSED
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

    // RESPONSE_PROPOSED -> VOTING
    function startVoting(
        bytes32 incidentId
    ) external onlyFederatedVoting {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");
        require(
            incident.state == IncidentState.RESPONSE_PROPOSED,
            "Incident not RESPONSE_PROPOSED"
        );

        IncidentState oldState = incident.state;
        incident.state = IncidentState.VOTING;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            incident.state
        );
    }

    // VOTING -> APPROVED or CLOSED
    function finalizeIncidentDecision(
        bytes32 incidentId,
        bool approved
    ) external onlyResponseDecision {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");
        require(
            incident.state == IncidentState.VOTING,
            "Incident not VOTING"
        );

        IncidentState oldState = incident.state;
        incident.state = approved
            ? IncidentState.APPROVED
            : IncidentState.CLOSED;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            incident.state
        );
    }

    // APPROVED -> EXECUTING
    function startExecution(
        bytes32 incidentId
    ) external onlyExecutionContract {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");
        require(
            incident.state == IncidentState.APPROVED,
            "Incident not APPROVED"
        );

        IncidentState oldState = incident.state;
        incident.state = IncidentState.EXECUTING;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            incident.state
        );
    }

    // EXECUTING -> VERIFIED
    function markIncidentVerified(
        bytes32 incidentId
    ) external onlyVerificationContract {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");
        require(
            incident.state == IncidentState.EXECUTING,
            "Incident not EXECUTING"
        );

        IncidentState oldState = incident.state;
        incident.state = IncidentState.VERIFIED;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            incident.state
        );
    }

    // VERIFIED -> CLOSED
    function closeVerifiedIncident(
        bytes32 incidentId
    ) external onlyVerificationContract {
        Incident storage incident = incidents[incidentId];

        require(incident.timestamp != 0, "Incident not found");
        require(
            incident.state == IncidentState.VERIFIED,
            "Incident not VERIFIED"
        );

        IncidentState oldState = incident.state;
        incident.state = IncidentState.CLOSED;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            incident.state
        );
    }

    // Only non-workflow transitions may be advanced by active domains.
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
            newState != IncidentState.RESPONSE_PROPOSED &&
            newState != IncidentState.VOTING &&
            newState != IncidentState.APPROVED &&
            newState != IncidentState.EXECUTING &&
            newState != IncidentState.VERIFIED &&
            newState != IncidentState.CLOSED,
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
