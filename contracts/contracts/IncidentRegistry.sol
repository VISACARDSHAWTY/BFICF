// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./DomainRegistry.sol";

/**
 * @title IncidentRegistry
 * @dev Manages incident registration and enforces the on-chain incident state machine.
 */
contract IncidentRegistry is AccessControl {
    bytes32 public constant DOMAIN_ROLE = keccak256("DOMAIN_ROLE");

    enum IncidentType { SOFTWARE, HARDWARE, CYBER }
    enum IncidentState { REGISTERED, CORRELATED, RESPONSE_PROPOSED, VOTING, APPROVED, EXECUTING, VERIFIED, CLOSED }

    struct Incident {
        bytes32 incidentHash;
        IncidentType incidentType;
        uint8 severity;
        uint256 timestamp;
        IncidentState state;
        address registeredBy;
    }

    // Mapping from incident ID to incident data
    mapping(bytes32 => Incident) public incidents;

    // DomainRegistry reference for permission checks
    DomainRegistry public immutable domainRegistry;

    event IncidentRegistered(bytes32 indexed incidentId, bytes32 incidentHash, IncidentType incidentType, uint8 severity, address registeredBy);
    event IncidentStateUpdated(bytes32 indexed incidentId, IncidentState oldState, IncidentState newState);

    constructor(address _domainRegistry) {
        domainRegistry = DomainRegistry(_domainRegistry);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Register a new incident. Only active domains can register.
     */
    function registerIncident(
        bytes32 incidentId,
        bytes32 incidentHash,
        IncidentType incidentType,
        uint8 severity
    ) external onlyRole(DOMAIN_ROLE) {
        require(incidents[incidentId].timestamp == 0, "Incident already registered");
        require(severity <= 10, "Invalid severity");

        incidents[incidentId] = Incident({
            incidentHash: incidentHash,
            incidentType: incidentType,
            severity: severity,
            timestamp: block.timestamp,
            state: IncidentState.REGISTERED,
            registeredBy: msg.sender
        });

        emit IncidentRegistered(incidentId, incidentHash, incidentType, severity, msg.sender);
    }

    /**
     * @dev Advance the incident state. Only active domains can advance.
     */
    function advanceState(bytes32 incidentId, IncidentState newState) external onlyRole(DOMAIN_ROLE) {
        IncidentState oldState = incidents[incidentId].state;
        require(oldState != newState, "Invalid transition");

        // Enforce legal state transitions
        if (oldState == IncidentState.REGISTERED) {
            require(newState == IncidentState.CORRELATED, "Invalid transition");
        } else if (oldState == IncidentState.CORRELATED) {
            require(newState == IncidentState.RESPONSE_PROPOSED, "Invalid transition");
        } else if (oldState == IncidentState.RESPONSE_PROPOSED) {
            require(newState == IncidentState.VOTING, "Invalid transition");
        } else if (oldState == IncidentState.VOTING) {
            require(newState == IncidentState.APPROVED, "Invalid transition");
        } else if (oldState == IncidentState.APPROVED) {
            require(newState == IncidentState.EXECUTING, "Invalid transition");
        } else if (oldState == IncidentState.EXECUTING) {
            require(newState == IncidentState.VERIFIED, "Invalid transition");
        } else if (oldState == IncidentState.VERIFIED) {
            require(newState == IncidentState.CLOSED, "Invalid transition");
        } else {
            revert("Invalid transition");
        }

        incidents[incidentId].state = newState;
        emit IncidentStateUpdated(incidentId, oldState, newState);
    }
}