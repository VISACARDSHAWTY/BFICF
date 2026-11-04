// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface IDomainRegistryExecution {
    function isActiveDomain(address domain) external view returns (bool);
    function isSecurityAuthority(address account) external view returns (bool);
}

interface IResponseDecisionExecution {
    function decisions(uint256 proposalId)
        external
        view
        returns (
            uint8 outcome,
            uint256 validVotes,
            uint256 eligibleVoters,
            bool quorumReached,
            uint256 timestamp,
            bool finalized
        );
}

interface IResponseProposalExecution {
    function proposals(uint256 proposalId)
        external
        view
        returns (
            bytes32 incidentId,
            address proposer,
            address targetDomain,
            bytes32 targetResourceId,
            bytes32 detailsHash,
            uint256 createdAt,
            uint256 votingDeadline,
            uint8 status
        );

    function isEligibleVoter(uint256 proposalId, address voter) external view returns (bool);
    function hasAction(uint256 proposalId, uint8 action) external view returns (bool);
}

interface IIncidentRegistryExecution {
    function startExecution(bytes32 incidentId) external;
    function escalateIncident(bytes32 incidentId) external;
}

/**
 * @title ResponseExecution
 * @dev Execution plan for an APPROVED proposal.
 *
 *  The plan is validated against the proposal and the decision on-chain:
 *   - the proposal must be APPROVED and its decision finalized (outcome QUARANTINE/PATCH/REVOKE/MONITOR);
 *   - every action must be either one of the proposal's actions or the action matching the
 *     winning outcome, and the plan MUST contain the winning outcome's action;
 *   - the target resource is taken from the proposal (not from the caller).
 *  Any affected domain (eligible voter) or the proposer - i.e. any domain's DIC - may create the plan,
 *  so there is no single "DIC" trust anchor.
 *
 *  A plan has a deadline; if it is not fully verified by then, anyone can escalate it.
 */
contract ResponseExecution {
    // Mirrors ResponseProposal.ResponseAction numbering.
    uint8 public constant ACTION_QUARANTINE = 0;
    uint8 public constant ACTION_PATCH = 1;
    uint8 public constant ACTION_REVOKE = 2;
    uint8 public constant ACTION_BLOCK_TRAFFIC = 3;
    uint8 public constant ACTION_MONITOR = 4;
    uint8 public constant ACTION_NO_ACTION = 5;

    uint256 public constant MAX_ACTIONS = 16;

    enum ActionStatus { PENDING, SUBMITTED, VERIFIED, FAILED }

    struct ActionInput {
        address responsibleDomain;
        uint8 actionType;
        bytes32 detailsHash;
    }

    struct ExecutionAction {
        uint256 proposalId;
        bytes32 incidentId;
        address responsibleDomain;
        uint8 actionType;
        bytes32 targetResourceId;
        bytes32 detailsHash;
        bytes32 receiptHash;
        uint256 reportedAt;
        ActionStatus status;
    }

    struct ExecutionPlan {
        bytes32 incidentId;
        uint256 totalActions;
        uint256 verifiedActions;
        uint256 deadline;
        bool created;
        bool escalated;
    }

    address public verificationContract;
    uint256 public executionWindow;
    uint256 public nextActionId = 1;

    IDomainRegistryExecution public immutable domainRegistry;
    IResponseDecisionExecution public immutable responseDecision;
    IResponseProposalExecution public immutable responseProposal;
    IIncidentRegistryExecution public immutable incidentRegistry;

    mapping(uint256 => ExecutionPlan) public executionPlans;
    mapping(uint256 => ExecutionAction) private actions;
    mapping(uint256 => uint256[]) private proposalActionIds;

    event VerificationContractUpdated(address indexed verifier);
    event ExecutionWindowUpdated(uint256 window);
    event ExecutionPlanCreated(
        uint256 indexed proposalId,
        bytes32 indexed incidentId,
        uint256 totalActions,
        uint256 deadline
    );
    event ActionAssigned(
        uint256 indexed actionId,
        uint256 indexed proposalId,
        address indexed responsibleDomain,
        uint8 actionType,
        bytes32 targetResourceId
    );
    event ExecutionReported(
        uint256 indexed actionId,
        address indexed responsibleDomain,
        bytes32 receiptHash,
        uint256 timestamp
    );
    event ActionVerificationUpdated(uint256 indexed actionId, ActionStatus status);
    event ExecutionEscalated(uint256 indexed proposalId, bytes32 indexed incidentId);

    modifier onlySecAuth() {
        require(domainRegistry.isSecurityAuthority(msg.sender), "Not Security Authority");
        _;
    }

    modifier onlyVerificationContract() {
        require(
            msg.sender == verificationContract && verificationContract != address(0),
            "Not verification contract"
        );
        _;
    }

    constructor(
        address _domainRegistry,
        address _responseDecision,
        address _responseProposal,
        address _incidentRegistry,
        uint256 _executionWindow
    ) {
        require(_domainRegistry != address(0), "Invalid domain registry");
        require(_responseDecision != address(0), "Invalid decision contract");
        require(_responseProposal != address(0), "Invalid proposal contract");
        require(_incidentRegistry != address(0), "Invalid incident registry");
        require(_executionWindow > 0, "Invalid execution window");

        domainRegistry = IDomainRegistryExecution(_domainRegistry);
        responseDecision = IResponseDecisionExecution(_responseDecision);
        responseProposal = IResponseProposalExecution(_responseProposal);
        incidentRegistry = IIncidentRegistryExecution(_incidentRegistry);
        executionWindow = _executionWindow;
    }

    /// @dev Write-once wiring.
    function setVerificationContract(address _verificationContract) external onlySecAuth {
        require(verificationContract == address(0), "Verification already set");
        require(_verificationContract != address(0), "Invalid verification address");
        verificationContract = _verificationContract;
        emit VerificationContractUpdated(_verificationContract);
    }

    function setExecutionWindow(uint256 _window) external onlySecAuth {
        require(_window > 0, "Invalid execution window");
        executionWindow = _window;
        emit ExecutionWindowUpdated(_window);
    }

    // ------------------------------------------------------------------
    // Plan creation
    // ------------------------------------------------------------------

    function createExecutionPlan(uint256 proposalId, ActionInput[] calldata inputs) external {
        require(!executionPlans[proposalId].created, "Execution plan already exists");
        require(inputs.length > 0, "No actions provided");
        require(inputs.length <= MAX_ACTIONS, "Too many actions");
        require(domainRegistry.isActiveDomain(msg.sender), "Not an active domain");

        uint8 decidedAction = _decidedAction(proposalId);

        (bytes32 incidentId, bytes32 target) = _authoriseAndLoad(proposalId);

        uint256 deadline = block.timestamp + executionWindow;

        executionPlans[proposalId] = ExecutionPlan({
            incidentId: incidentId,
            totalActions: inputs.length,
            verifiedActions: 0,
            deadline: deadline,
            created: true,
            escalated: false
        });

        bool covered;
        for (uint256 i = 0; i < inputs.length; i++) {
            if (_storeAction(proposalId, incidentId, target, decidedAction, inputs[i])) {
                covered = true;
            }
        }
        require(covered, "Plan lacks decided action");

        // APPROVED -> EXECUTING
        incidentRegistry.startExecution(incidentId);

        emit ExecutionPlanCreated(proposalId, incidentId, inputs.length, deadline);
    }

    function _decidedAction(uint256 proposalId) internal view returns (uint8 action) {
        (uint8 outcome, , , , , bool finalized) = responseDecision.decisions(proposalId);

        require(finalized, "Decision not finalized");
        require(outcome <= 3, "Decision requires no execution"); // excludes NO_ACTION / NO_QUORUM

        // DecisionOutcome {QUARANTINE, PATCH, REVOKE, MONITOR} -> ResponseAction
        if (outcome == 0) return ACTION_QUARANTINE;
        if (outcome == 1) return ACTION_PATCH;
        if (outcome == 2) return ACTION_REVOKE;
        return ACTION_MONITOR;
    }

    function _authoriseAndLoad(uint256 proposalId) internal view returns (bytes32 incidentId, bytes32 target) {
        address proposer;
        uint256 createdAt;
        uint8 status;
        (incidentId, proposer, , target, , createdAt, , status) = responseProposal.proposals(proposalId);

        require(createdAt != 0, "Proposal not found");
        require(status == 1, "Proposal not approved");
        require(
            msg.sender == proposer || responseProposal.isEligibleVoter(proposalId, msg.sender),
            "Not authorised for plan"
        );
    }

    function _storeAction(
        uint256 proposalId,
        bytes32 incidentId,
        bytes32 target,
        uint8 decidedAction,
        ActionInput calldata input
    ) internal returns (bool isDecided) {
        require(domainRegistry.isActiveDomain(input.responsibleDomain), "Inactive responsible domain");

        isDecided = input.actionType == decidedAction;
        require(
            isDecided || (input.actionType != ACTION_NO_ACTION && responseProposal.hasAction(proposalId, input.actionType)),
            "Action not in proposal"
        );

        uint256 actionId = nextActionId++;

        actions[actionId] = ExecutionAction({
            proposalId: proposalId,
            incidentId: incidentId,
            responsibleDomain: input.responsibleDomain,
            actionType: input.actionType,
            targetResourceId: target,
            detailsHash: input.detailsHash,
            receiptHash: bytes32(0),
            reportedAt: 0,
            status: ActionStatus.PENDING
        });
        proposalActionIds[proposalId].push(actionId);

        emit ActionAssigned(actionId, proposalId, input.responsibleDomain, input.actionType, target);
    }

    // ------------------------------------------------------------------
    // Reporting / verification hooks
    // ------------------------------------------------------------------

    function reportExecution(uint256 actionId, bytes32 receiptHash) external {
        ExecutionAction storage action = actions[actionId];

        require(action.proposalId != 0, "Action not found");
        require(msg.sender == action.responsibleDomain, "Not assigned domain");
        require(!executionPlans[action.proposalId].escalated, "Plan escalated");
        require(receiptHash != bytes32(0), "Invalid receipt hash");
        require(receiptHash != action.receiptHash, "Receipt must differ from previous");
        require(
            action.status == ActionStatus.PENDING || action.status == ActionStatus.FAILED,
            "Action already submitted"
        );

        action.receiptHash = receiptHash;
        action.reportedAt = block.timestamp;
        action.status = ActionStatus.SUBMITTED;

        emit ExecutionReported(actionId, msg.sender, receiptHash, block.timestamp);
    }

    function markActionVerified(uint256 actionId, bool successful) external onlyVerificationContract {
        ExecutionAction storage action = actions[actionId];

        require(action.proposalId != 0, "Action not found");
        require(action.status == ActionStatus.SUBMITTED, "Action not submitted");

        if (successful) {
            action.status = ActionStatus.VERIFIED;
            executionPlans[action.proposalId].verifiedActions++;
        } else {
            action.status = ActionStatus.FAILED;
        }

        emit ActionVerificationUpdated(actionId, action.status);
    }

    /// @dev Anyone may escalate a plan that missed its deadline: EXECUTING -> ESCALATED.
    function escalateStalled(uint256 proposalId) external {
        ExecutionPlan storage plan = executionPlans[proposalId];

        require(plan.created, "Execution plan not found");
        require(!plan.escalated, "Already escalated");
        require(plan.verifiedActions < plan.totalActions, "Plan complete");
        require(block.timestamp > plan.deadline, "Deadline not reached");

        plan.escalated = true;
        incidentRegistry.escalateIncident(plan.incidentId);

        emit ExecutionEscalated(proposalId, plan.incidentId);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function getAction(uint256 actionId) external view returns (ExecutionAction memory) {
        require(actions[actionId].proposalId != 0, "Action not found");
        return actions[actionId];
    }

    function getProposalActionIds(uint256 proposalId) external view returns (uint256[] memory) {
        return proposalActionIds[proposalId];
    }

    function getPlanProgress(uint256 proposalId)
        external
        view
        returns (bytes32 incidentId, uint256 totalActions, uint256 verifiedActions, bool complete)
    {
        ExecutionPlan storage plan = executionPlans[proposalId];
        require(plan.created, "Execution plan not found");

        return (plan.incidentId, plan.totalActions, plan.verifiedActions, plan.verifiedActions == plan.totalActions);
    }
}
