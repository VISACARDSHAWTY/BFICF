
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface IDomainRegistryExecution {
    function isActiveDomain(address domain)
        external
        view
        returns (bool);
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
}

interface IIncidentRegistryExecution {
    function startExecution(bytes32 incidentId) external;
}

contract ResponseExecution {
    enum ActionStatus {
        PENDING,
        SUBMITTED,
        VERIFIED,
        FAILED
    }

    struct ActionInput {
        address responsibleDomain;
        bytes32 actionType;
        bytes32 targetResourceId;
        bytes32 detailsHash;
    }

    struct ExecutionAction {
        uint256 proposalId;
        bytes32 incidentId;
        address responsibleDomain;
        bytes32 actionType;
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
        bool created;
    }

    address public admin;
    address public dic;
    address public verificationContract;

    IDomainRegistryExecution public immutable domainRegistry;
    IResponseDecisionExecution public immutable responseDecision;
    IResponseProposalExecution public immutable responseProposal;
    IIncidentRegistryExecution public immutable incidentRegistry;

    uint256 public nextActionId = 1;

    mapping(uint256 => ExecutionPlan) public executionPlans;
    mapping(uint256 => ExecutionAction) private actions;

    event DICUpdated(address indexed dic);
    event VerificationContractUpdated(address indexed verifier);

    event ExecutionPlanCreated(
        uint256 indexed proposalId,
        bytes32 indexed incidentId,
        uint256 totalActions
    );

    event ActionAssigned(
        uint256 indexed actionId,
        uint256 indexed proposalId,
        address indexed responsibleDomain,
        bytes32 actionType,
        bytes32 targetResourceId
    );

    event ExecutionReported(
        uint256 indexed actionId,
        address indexed responsibleDomain,
        bytes32 receiptHash,
        uint256 timestamp
    );

    event ActionVerificationUpdated(
        uint256 indexed actionId,
        ActionStatus status
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyDIC() {
        require(msg.sender == dic && dic != address(0), "Not DIC");
        _;
    }

    modifier onlyVerificationContract() {
        require(
            msg.sender == verificationContract &&
            verificationContract != address(0),
            "Not verification contract"
        );
        _;
    }

    constructor(
        address _domainRegistry,
        address _responseDecision,
        address _responseProposal,
        address _incidentRegistry
    ) {
        require(_domainRegistry != address(0), "Invalid domain registry");
        require(_responseDecision != address(0), "Invalid decision contract");
        require(_responseProposal != address(0), "Invalid proposal contract");
        require(_incidentRegistry != address(0), "Invalid incident registry");

        domainRegistry = IDomainRegistryExecution(_domainRegistry);
        responseDecision = IResponseDecisionExecution(_responseDecision);
        responseProposal = IResponseProposalExecution(_responseProposal);
        incidentRegistry = IIncidentRegistryExecution(_incidentRegistry);

        admin = msg.sender;
    }

    function setDIC(address _dic) external onlyAdmin {
        require(_dic != address(0), "Invalid DIC address");
        dic = _dic;
        emit DICUpdated(_dic);
    }

    function setVerificationContract(
        address _verificationContract
    ) external onlyAdmin {
        require(
            _verificationContract != address(0),
            "Invalid verification address"
        );

        verificationContract = _verificationContract;

        emit VerificationContractUpdated(_verificationContract);
    }

    function createExecutionPlan(
        uint256 proposalId,
        ActionInput[] calldata actionInputs
    ) external onlyDIC {
        require(
            !executionPlans[proposalId].created,
            "Execution plan already exists"
        );

        require(actionInputs.length > 0, "No actions provided");

        (
            uint8 outcome,
            ,
            ,
            ,
            ,
            bool decisionFinalized
        ) = responseDecision.decisions(proposalId);

        require(decisionFinalized, "Decision not finalized");
        require(outcome != 4, "Decision is NO_ACTION");

        (
            bytes32 incidentId,
            ,
            ,
            ,
            ,
            uint256 createdAt,
            ,
        ) = responseProposal.proposals(proposalId);

        require(createdAt != 0, "Proposal not found");

        executionPlans[proposalId] = ExecutionPlan({
            incidentId: incidentId,
            totalActions: actionInputs.length,
            verifiedActions: 0,
            created: true
        });

        for (uint256 i = 0; i < actionInputs.length; i++) {
            ActionInput calldata input = actionInputs[i];

            require(
                domainRegistry.isActiveDomain(input.responsibleDomain),
                "Inactive responsible domain"
            );

            require(
                input.actionType != bytes32(0),
                "Invalid action type"
            );

            uint256 actionId = nextActionId++;

            actions[actionId] = ExecutionAction({
                proposalId: proposalId,
                incidentId: incidentId,
                responsibleDomain: input.responsibleDomain,
                actionType: input.actionType,
                targetResourceId: input.targetResourceId,
                detailsHash: input.detailsHash,
                receiptHash: bytes32(0),
                reportedAt: 0,
                status: ActionStatus.PENDING
            });

            emit ActionAssigned(
                actionId,
                proposalId,
                input.responsibleDomain,
                input.actionType,
                input.targetResourceId
            );
        }

        // APPROVED -> EXECUTING
        incidentRegistry.startExecution(incidentId);

        emit ExecutionPlanCreated(
            proposalId,
            incidentId,
            actionInputs.length
        );
    }

    function reportExecution(
        uint256 actionId,
        bytes32 receiptHash
    ) external {
        ExecutionAction storage action = actions[actionId];

        require(
            action.proposalId != 0,
            "Action not found"
        );

        require(
            msg.sender == action.responsibleDomain,
            "Not assigned domain"
        );

        require(receiptHash != bytes32(0), "Invalid receipt hash");

        require(
            action.status == ActionStatus.PENDING ||
            action.status == ActionStatus.FAILED,
            "Action already submitted"
        );

        action.receiptHash = receiptHash;
        action.reportedAt = block.timestamp;
        action.status = ActionStatus.SUBMITTED;

        emit ExecutionReported(
            actionId,
            msg.sender,
            receiptHash,
            block.timestamp
        );
    }

    function markActionVerified(
        uint256 actionId,
        bool successful
    ) external onlyVerificationContract {
        ExecutionAction storage action = actions[actionId];

        require(action.proposalId != 0, "Action not found");
        require(
            action.status == ActionStatus.SUBMITTED,
            "Action not submitted"
        );

        if (successful) {
            action.status = ActionStatus.VERIFIED;

            executionPlans[action.proposalId].verifiedActions++;
        } else {
            action.status = ActionStatus.FAILED;
        }

        emit ActionVerificationUpdated(
            actionId,
            action.status
        );
    }

    function getAction(
        uint256 actionId
    ) external view returns (ExecutionAction memory) {
        require(actions[actionId].proposalId != 0, "Action not found");
        return actions[actionId];
    }

    function getPlanProgress(
        uint256 proposalId
    )
        external
        view
        returns (
            bytes32 incidentId,
            uint256 totalActions,
            uint256 verifiedActions,
            bool complete
        )
    {
        ExecutionPlan storage plan = executionPlans[proposalId];

        require(plan.created, "Execution plan not found");

        return (
            plan.incidentId,
            plan.totalActions,
            plan.verifiedActions,
            plan.verifiedActions == plan.totalActions
        );
    }
}
