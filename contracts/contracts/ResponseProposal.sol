
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

interface IIncidentRegistryProposal {
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

    function markResponseProposed(bytes32 incidentId) external;
}

interface ICorrelationDecisionProposal {
    function hasCorrelation(bytes32 incidentId)
        external
        view
        returns (bool);

    function isAffectedDomain(
        bytes32 incidentId,
        address domain
    ) external view returns (bool);

    function correlations(bytes32 incidentId)
        external
        view
        returns (
            bytes32 resultHash,
            bytes32 algorithmVersionHash,
            uint8 confidence,
            uint256 timestamp,
            address submittedBy,
            bool exists
        );
}

contract ResponseProposal {
    enum ResponseAction {
        QUARANTINE,
        PATCH,
        REVOKE,
        BLOCK_TRAFFIC,
        MONITOR,
        NO_ACTION
    }

    enum ProposalStatus {
        PENDING,
        APPROVED,
        REJECTED,
        EXPIRED
    }

    struct Proposal {
        bytes32 incidentId;
        address proposer;
        address targetDomain;
        bytes32 targetResourceId;
        bytes32 detailsHash;
        uint256 createdAt;
        uint256 votingDeadline;
        ProposalStatus status;
    }

    uint256 public constant MIN_VOTING_PERIOD = 5 minutes;
    uint256 public constant MAX_VOTING_PERIOD = 7 days;

    uint256 public nextProposalId = 1;

    address public admin;
    address public responseDecision;

    uint8 public minimumConfidenceClass;

    DomainRegistry public immutable domainRegistry;
    IIncidentRegistryProposal public immutable incidentRegistry;
    ICorrelationDecisionProposal public immutable correlationDecision;

    mapping(uint256 => Proposal) public proposals;

    mapping(uint256 => ResponseAction[]) private proposalActions;
    mapping(uint256 => address[]) private eligibleVoters;

    mapping(uint256 => mapping(address => bool))
        public isEligibleVoter;

    event ProposalCreated(
        uint256 indexed proposalId,
        bytes32 indexed incidentId,
        address indexed proposer,
        address targetDomain,
        bytes32 targetResourceId,
        uint256 votingDeadline
    );

    event ProposalActionAdded(
        uint256 indexed proposalId,
        ResponseAction action
    );

    event EligibleVoterAdded(
        uint256 indexed proposalId,
        address indexed voter
    );

    event ProposalExpired(uint256 indexed proposalId);

    event MinimumConfidenceUpdated(uint8 newMinimum);

    event ResponseDecisionUpdated(address responseDecision);

    event ProposalFinalized(
        uint256 indexed proposalId,
        ProposalStatus status
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

    modifier onlyResponseDecision() {
        require(
            msg.sender == responseDecision &&
            responseDecision != address(0),
            "Not decision contract"
        );
        _;
    }

    constructor(
        address _domainRegistry,
        address _incidentRegistry,
        address _correlationDecision,
        uint8 _minimumConfidenceClass
    ) {
        require(
            _domainRegistry != address(0),
            "Invalid domain registry"
        );
        require(
            _incidentRegistry != address(0),
            "Invalid incident registry"
        );
        require(
            _correlationDecision != address(0),
            "Invalid correlation contract"
        );
        require(
            _minimumConfidenceClass <= 3,
            "Invalid confidence class"
        );

        domainRegistry = DomainRegistry(_domainRegistry);
        incidentRegistry =
            IIncidentRegistryProposal(_incidentRegistry);
        correlationDecision =
            ICorrelationDecisionProposal(_correlationDecision);

        admin = msg.sender;
        minimumConfidenceClass = _minimumConfidenceClass;
    }

    function setMinimumConfidenceClass(
        uint8 newMinimum
    ) external onlyAdmin {
        require(newMinimum <= 3, "Invalid confidence class");

        minimumConfidenceClass = newMinimum;

        emit MinimumConfidenceUpdated(newMinimum);
    }

    function setResponseDecision(
        address _responseDecision
    ) external onlyAdmin {
        require(
            _responseDecision != address(0),
            "Invalid decision address"
        );

        responseDecision = _responseDecision;

        emit ResponseDecisionUpdated(_responseDecision);
    }

    function createProposal(
        bytes32 incidentId,
        address targetDomain,
        bytes32 targetResourceId,
        ResponseAction[] calldata actions,
        bytes32 detailsHash,
        address[] calldata voters,
        uint256 votingDuration
    ) external onlyActiveDomain returns (uint256) {
        require(incidentId != bytes32(0), "Invalid incident ID");
        require(targetDomain != address(0), "Invalid target domain");
        require(
            targetResourceId != bytes32(0),
            "Invalid target resource"
        );
        require(detailsHash != bytes32(0), "Invalid details hash");

        require(
            domainRegistry.isActiveDomain(targetDomain),
            "Target domain not active"
        );

        require(
            correlationDecision.hasCorrelation(incidentId),
            "Incident not correlated"
        );

        require(
            correlationDecision.isAffectedDomain(
                incidentId,
                targetDomain
            ),
            "Target domain not affected"
        );

        (
            ,
            ,
            ,
            uint256 incidentTimestamp,
            uint8 incidentState,

        ) = incidentRegistry.incidents(incidentId);

        require(incidentTimestamp != 0, "Incident not found");
        require(incidentState == 1, "Incident not CORRELATED");

        (
            ,
            ,
            uint8 confidence,
            ,
            ,
            bool correlationExists
        ) = correlationDecision.correlations(incidentId);

        require(correlationExists, "Correlation not found");
        require(
            confidence >= minimumConfidenceClass,
            "Insufficient correlation confidence"
        );

        require(actions.length > 0, "No response actions");
        require(voters.length > 0, "No eligible voters");

        require(
            votingDuration >= MIN_VOTING_PERIOD,
            "Voting period too short"
        );
        require(
            votingDuration <= MAX_VOTING_PERIOD,
            "Voting period too long"
        );

        // All voters must be active affected domains.
        for (uint256 i = 0; i < voters.length; i++) {
            address voter = voters[i];

            require(voter != address(0), "Invalid voter");
            require(
                domainRegistry.isActiveDomain(voter),
                "Voter not active"
            );
            require(
                correlationDecision.isAffectedDomain(
                    incidentId,
                    voter
                ),
                "Voter not affected"
            );

            for (uint256 j = 0; j < i; j++) {
                require(
                    voters[j] != voter,
                    "Duplicate voter"
                );
            }
        }

        // Prevent duplicate actions within one proposal.
        for (uint256 i = 0; i < actions.length; i++) {
            for (uint256 j = 0; j < i; j++) {
                require(
                    actions[i] != actions[j],
                    "Duplicate response action"
                );
            }
        }

        uint256 proposalId = nextProposalId++;
        uint256 deadline = block.timestamp + votingDuration;

        proposals[proposalId] = Proposal({
            incidentId: incidentId,
            proposer: msg.sender,
            targetDomain: targetDomain,
            targetResourceId: targetResourceId,
            detailsHash: detailsHash,
            createdAt: block.timestamp,
            votingDeadline: deadline,
            status: ProposalStatus.PENDING
        });

        for (uint256 i = 0; i < actions.length; i++) {
            proposalActions[proposalId].push(actions[i]);

            emit ProposalActionAdded(proposalId, actions[i]);
        }

        for (uint256 i = 0; i < voters.length; i++) {
            eligibleVoters[proposalId].push(voters[i]);

            isEligibleVoter[proposalId][voters[i]] = true;

            emit EligibleVoterAdded(proposalId, voters[i]);
        }

        emit ProposalCreated(
            proposalId,
            incidentId,
            msg.sender,
            targetDomain,
            targetResourceId,
            deadline
        );

        // Automatically changes CORRELATED -> RESPONSE_PROPOSED.
        incidentRegistry.markResponseProposed(incidentId);

        return proposalId;
    }

    function getActions(
        uint256 proposalId
    ) external view returns (ResponseAction[] memory) {
        require(
            proposals[proposalId].createdAt != 0,
            "Proposal not found"
        );

        return proposalActions[proposalId];
    }

    function getEligibleVoters(
        uint256 proposalId
    ) external view returns (address[] memory) {
        require(
            proposals[proposalId].createdAt != 0,
            "Proposal not found"
        );

        return eligibleVoters[proposalId];
    }

    function isVotingOpen(
        uint256 proposalId
    ) public view returns (bool) {
        Proposal storage proposal = proposals[proposalId];

        return
            proposal.createdAt != 0 &&
            proposal.status == ProposalStatus.PENDING &&
            block.timestamp < proposal.votingDeadline;
    }

    function finalizeProposal(
        uint256 proposalId,
        bool approved
    ) external onlyResponseDecision {
        Proposal storage proposal = proposals[proposalId];

        require(
            proposal.createdAt != 0,
            "Proposal not found"
        );

        require(
            proposal.status == ProposalStatus.PENDING,
            "Proposal not pending"
        );

        proposal.status = approved
            ? ProposalStatus.APPROVED
            : ProposalStatus.REJECTED;

        emit ProposalFinalized(
            proposalId,
            proposal.status
        );
    }

    function expireProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(proposal.createdAt != 0, "Proposal not found");
        require(
            proposal.status == ProposalStatus.PENDING,
            "Proposal not pending"
        );
        require(
            block.timestamp >= proposal.votingDeadline,
            "Voting period not ended"
        );

        proposal.status = ProposalStatus.EXPIRED;

        emit ProposalExpired(proposalId);
    }
}
