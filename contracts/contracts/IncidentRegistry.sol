
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

/**
 * @title IncidentRegistry
 * @dev Manages incident registration and enforces the on-chain incident state machine.
 */
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

    event IncidentRegistered(
        bytes32 indexed incidentId,
        bytes32 incidentHash,
        IncidentType incidentType,
        uint8 severity,
        address registeredBy
    );

    event IncidentStateUpdated(
        bytes32 indexed incidentId,
        IncidentState oldState,
        IncidentState newState
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
     * @dev Register an incident. Only active domains can register.
     */
    function registerIncident(
        bytes32 incidentId,
        bytes32 incidentHash,
        IncidentType incidentType,
        uint8 severity
    ) external onlyActiveDomain {

        require(
            incidents[incidentId].timestamp == 0,
            "Incident already registered"
        );

        require(severity <= 10, "Invalid severity");

        incidents[incidentId] = Incident({
            incidentHash: incidentHash,
            incidentType: incidentType,
            severity: severity,
            timestamp: block.timestamp,
            state: IncidentState.REGISTERED,
            registeredBy: msg.sender
        });

        emit IncidentRegistered(
            incidentId,
            incidentHash,
            incidentType,
            severity,
            msg.sender
        );
    }

    /**
     * @dev Advance incident state following legal transitions.
     */
    function advanceState(
        bytes32 incidentId,
        IncidentState newState
    ) external onlyActiveDomain {

        require(
            incidents[incidentId].timestamp != 0,
            "Incident not found"
        );

        IncidentState oldState = incidents[incidentId].state;

        require(oldState != newState, "Invalid transition");

        if (oldState == IncidentState.REGISTERED) {
            require(
                newState == IncidentState.CORRELATED,
                "Invalid transition"
            );
        } 
        else if (oldState == IncidentState.CORRELATED) {
            require(
                newState == IncidentState.RESPONSE_PROPOSED,
                "Invalid transition"
            );
        } 
        else if (oldState == IncidentState.RESPONSE_PROPOSED) {
            require(
                newState == IncidentState.VOTING,
                "Invalid transition"
            );
        } 
        else if (oldState == IncidentState.VOTING) {
            require(
                newState == IncidentState.APPROVED,
                "Invalid transition"
            );
        } 
        else if (oldState == IncidentState.APPROVED) {
            require(
                newState == IncidentState.EXECUTING,
                "Invalid transition"
            );
        } 
        else if (oldState == IncidentState.EXECUTING) {
            require(
                newState == IncidentState.VERIFIED,
                "Invalid transition"
            );
        } 
        else if (oldState == IncidentState.VERIFIED) {
            require(
                newState == IncidentState.CLOSED,
                "Invalid transition"
            );
        } 
        else {
            revert("Invalid transition");
        }

        incidents[incidentId].state = newState;

        emit IncidentStateUpdated(
            incidentId,
            oldState,
            newState
        );
    }
}
