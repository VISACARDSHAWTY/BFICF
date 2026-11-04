// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

/**
 * @title IncidentRegistry
 * @dev On-chain incident state machine.
 *
 *  REGISTERED -> CORRELATED -> RESPONSE_PROPOSED -> VOTING -> APPROVED -> EXECUTING
 *             -> VERIFIED -> CLOSED
 *
 *  Exceptional paths (liveness):
 *    VOTING            -> CLOSED     federation explicitly voted NO_ACTION
 *    RESPONSE_PROPOSED / VOTING / EXECUTING / APPROVED -> ESCALATED
 *                                    (proposal expired, no quorum, execution stalled,
 *                                     approved-but-never-executed)
 *    ESCALATED         -> CORRELATED Security Authority re-opens for a new proposal
 *
 *  Workflow-contract wiring is WRITE-ONCE: after setup nobody (including the Security
 *  Authority) can re-point a workflow address, so no single party can forge transitions.
 */
contract IncidentRegistry {
    enum IncidentType { SOFTWARE, HARDWARE, CYBER }

    enum IncidentState {
        REGISTERED,
        CORRELATED,
        RESPONSE_PROPOSED,
        VOTING,
        APPROVED,
        EXECUTING,
        VERIFIED,
        CLOSED,
        ESCALATED
    }

    struct Incident {
        bytes32 vectorCommitment; // H(IV_i) - commitment to the off-chain incident vector
        IncidentType incidentType;
        uint8 severity;
        uint256 detectedAt;       // domain-claimed detection time
        uint256 registeredAt;     // block time (authoritative)
        IncidentState state;
        address registeredBy;
        bytes32 closureHash;      // commitment to the off-chain closure record
    }

    uint256 public constant MAX_CLOCK_SKEW = 5 minutes;

    mapping(bytes32 => Incident) public incidents;

    DomainRegistry public immutable domainRegistry;

    address public correlationDecision;
    address public responseProposal;
    address public federatedVoting;
    address public responseDecision;
    address public coordinatedResponseExecution;
    address public executionVerification;

    event IncidentRegistered(
        bytes32 indexed incidentId,
        address indexed registeredBy,
        bytes32 vectorCommitment,
        IncidentType incidentType,
        uint8 severity,
        uint256 detectedAt
    );
    event IncidentStateUpdated(bytes32 indexed incidentId, IncidentState oldState, IncidentState newState);
    event IncidentClosed(bytes32 indexed incidentId, address indexed closedBy, bytes32 closureHash);
    event WorkflowContractsUpdated(address correlationDecision, address responseProposal);
    event GovernanceContractsUpdated(address federatedVoting, address responseDecision);
    event ExecutionContractsUpdated(address coordinatedResponseExecution, address executionVerification);

    modifier onlySecAuth() {
        require(domainRegistry.isSecurityAuthority(msg.sender), "Not Security Authority");
        _;
    }

    modifier onlyActiveDomain() {
        require(domainRegistry.isActiveDomain(msg.sender), "Not an active domain");
        _;
    }

    modifier onlyCorrelationDecision() {
        require(msg.sender == correlationDecision && correlationDecision != address(0), "Not correlation contract");
        _;
    }

    modifier onlyResponseProposal() {
        require(msg.sender == responseProposal && responseProposal != address(0), "Not response proposal contract");
        _;
    }

    modifier onlyFederatedVoting() {
        require(msg.sender == federatedVoting && federatedVoting != address(0), "Not voting contract");
        _;
    }

    modifier onlyResponseDecision() {
        require(msg.sender == responseDecision && responseDecision != address(0), "Not decision contract");
        _;
    }

    modifier onlyExecutionContract() {
        require(
            msg.sender == coordinatedResponseExecution && coordinatedResponseExecution != address(0),
            "Not execution contract"
        );
        _;
    }

    modifier onlyVerificationContract() {
        require(
            msg.sender == executionVerification && executionVerification != address(0),
            "Not verification contract"
        );
        _;
    }

    constructor(address _domainRegistry) {
        require(_domainRegistry != address(0), "Invalid registry address");
        domainRegistry = DomainRegistry(_domainRegistry);
    }

    // ------------------------------------------------------------------
    // One-time wiring (Security Authority)
    // ------------------------------------------------------------------

    function setWorkflowContracts(address _correlationDecision, address _responseProposal) external onlySecAuth {
        require(correlationDecision == address(0) && responseProposal == address(0), "Workflow already set");
        require(_correlationDecision != address(0), "Invalid correlation address");
        require(_responseProposal != address(0), "Invalid proposal address");

        correlationDecision = _correlationDecision;
        responseProposal = _responseProposal;
        emit WorkflowContractsUpdated(_correlationDecision, _responseProposal);
    }

    function setGovernanceContracts(address _federatedVoting, address _responseDecision) external onlySecAuth {
        require(federatedVoting == address(0) && responseDecision == address(0), "Governance already set");
        require(_federatedVoting != address(0), "Invalid voting address");
        require(_responseDecision != address(0), "Invalid decision address");

        federatedVoting = _federatedVoting;
        responseDecision = _responseDecision;
        emit GovernanceContractsUpdated(_federatedVoting, _responseDecision);
    }

    function setExecutionContracts(address _execution, address _verification) external onlySecAuth {
        require(
            coordinatedResponseExecution == address(0) && executionVerification == address(0),
            "Execution already set"
        );
        require(_execution != address(0), "Invalid execution address");
        require(_verification != address(0), "Invalid verification address");

        coordinatedResponseExecution = _execution;
        executionVerification = _verification;
        emit ExecutionContractsUpdated(_execution, _verification);
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    function registerIncident(
        bytes32 incidentId,
        bytes32 vectorCommitment,
        IncidentType incidentType,
        uint8 severity,
        uint256 detectedAt
    ) external onlyActiveDomain {
        require(incidentId != bytes32(0), "Invalid incident ID");
        require(vectorCommitment != bytes32(0), "Invalid vector commitment");
        require(detectedAt != 0 && detectedAt <= block.timestamp + MAX_CLOCK_SKEW, "Invalid timestamp");
        require(severity <= 10, "Invalid severity");
        require(incidents[incidentId].registeredAt == 0, "Incident already registered");

        incidents[incidentId] = Incident({
            vectorCommitment: vectorCommitment,
            incidentType: incidentType,
            severity: severity,
            detectedAt: detectedAt,
            registeredAt: block.timestamp,
            state: IncidentState.REGISTERED,
            registeredBy: msg.sender,
            closureHash: bytes32(0)
        });

        emit IncidentRegistered(incidentId, msg.sender, vectorCommitment, incidentType, severity, detectedAt);
    }

    // ------------------------------------------------------------------
    // Workflow transitions
    // ------------------------------------------------------------------

    // REGISTERED -> CORRELATED
    function markCorrelated(bytes32 incidentId) external onlyCorrelationDecision {
        _transition(incidentId, IncidentState.REGISTERED, IncidentState.CORRELATED);
    }

    // CORRELATED -> RESPONSE_PROPOSED
    function markResponseProposed(bytes32 incidentId) external onlyResponseProposal {
        _transition(incidentId, IncidentState.CORRELATED, IncidentState.RESPONSE_PROPOSED);
    }

    // RESPONSE_PROPOSED -> VOTING
    function startVoting(bytes32 incidentId) external onlyFederatedVoting {
        _transition(incidentId, IncidentState.RESPONSE_PROPOSED, IncidentState.VOTING);
    }

    // VOTING -> APPROVED (approved) or CLOSED (federation voted NO_ACTION)
    function finalizeIncidentDecision(bytes32 incidentId, bool approved) external onlyResponseDecision {
        _transition(
            incidentId,
            IncidentState.VOTING,
            approved ? IncidentState.APPROVED : IncidentState.CLOSED
        );
    }

    // APPROVED -> EXECUTING
    function startExecution(bytes32 incidentId) external onlyExecutionContract {
        _transition(incidentId, IncidentState.APPROVED, IncidentState.EXECUTING);
    }

    // EXECUTING -> VERIFIED
    function markIncidentVerified(bytes32 incidentId) external onlyVerificationContract {
        _transition(incidentId, IncidentState.EXECUTING, IncidentState.VERIFIED);
    }

    // VERIFIED -> CLOSED, with a commitment to the off-chain closure record.
    function closeIncident(bytes32 incidentId, bytes32 closureHash) external {
        require(
            domainRegistry.isActiveDomain(msg.sender) || domainRegistry.isSecurityAuthority(msg.sender),
            "Not authorised to close"
        );
        require(closureHash != bytes32(0), "Invalid closure hash");

        _transition(incidentId, IncidentState.VERIFIED, IncidentState.CLOSED);
        incidents[incidentId].closureHash = closureHash;

        emit IncidentClosed(incidentId, msg.sender, closureHash);
    }

    // ------------------------------------------------------------------
    // Liveness paths
    // ------------------------------------------------------------------

    /**
     * @dev Called by the contract responsible for the stalled phase:
     *      proposal contract (RESPONSE_PROPOSED expired), decision contract (VOTING, no quorum),
     *      execution contract (EXECUTING past its deadline).
     */
    function escalateIncident(bytes32 incidentId) external {
        IncidentState expected;

        if (msg.sender == responseProposal && responseProposal != address(0)) {
            expected = IncidentState.RESPONSE_PROPOSED;
        } else if (msg.sender == responseDecision && responseDecision != address(0)) {
            expected = IncidentState.VOTING;
        } else if (msg.sender == coordinatedResponseExecution && coordinatedResponseExecution != address(0)) {
            expected = IncidentState.EXECUTING;
        } else {
            revert("Not workflow contract");
        }

        _transition(incidentId, expected, IncidentState.ESCALATED);
    }

    /// @dev Approved by the federation but nobody created an execution plan.
    function forceEscalateApproved(bytes32 incidentId) external onlySecAuth {
        _transition(incidentId, IncidentState.APPROVED, IncidentState.ESCALATED);
    }

    /// @dev ESCALATED -> CORRELATED so a fresh proposal can be made.
    function reopenIncident(bytes32 incidentId) external onlySecAuth {
        _transition(incidentId, IncidentState.ESCALATED, IncidentState.CORRELATED);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function incidentExists(bytes32 incidentId) external view returns (bool) {
        return incidents[incidentId].registeredAt != 0;
    }

    function stateOf(bytes32 incidentId) external view returns (uint8) {
        require(incidents[incidentId].registeredAt != 0, "Incident not found");
        return uint8(incidents[incidentId].state);
    }

    function _transition(bytes32 incidentId, IncidentState expected, IncidentState next) internal {
        Incident storage incident = incidents[incidentId];

        require(incident.registeredAt != 0, "Incident not found");
        require(incident.state == expected, "Invalid incident state");

        incident.state = next;
        emit IncidentStateUpdated(incidentId, expected, next);
    }
}
