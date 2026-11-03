
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

interface IResponseProposalVoting {
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

    function getEligibleVoters(uint256 proposalId)
        external
        view
        returns (address[] memory);

    function isEligibleVoter(
        uint256 proposalId,
        address voter
    ) external view returns (bool);
}

interface IGovernanceParamsVoting {
    function quarantineThreshold() external view returns (uint256);
    function revokeThreshold() external view returns (uint256);
    function patchThreshold() external view returns (uint256);
    function quorumBasisPoints() external view returns (uint256);
    function commitWindow() external view returns (uint256);
    function revealWindow() external view returns (uint256);
}

interface IIncidentRegistryVoting {
    function startVoting(bytes32 incidentId) external;
}

interface IResponseDecisionVoting {
    function finalizeDecision(uint256 proposalId) external;
}

contract FederatedVoting {
    enum VoteChoice {
        QUARANTINE,
        PATCH,
        REVOKE,
        MONITOR,
        NO_ACTION
    }

    struct VotingSession {
        bool started;
        bool finalized;
        uint256 commitEnd;
        uint256 revealEnd;
        uint256 eligibleCount;
        uint256 revealedCount;

        // Governance parameters snapshotted at voting start.
        uint256 quarantineThreshold;
        uint256 revokeThreshold;
        uint256 patchThreshold;
        uint256 quorumBasisPoints;
    }

    address public admin;
    address public responseDecision;

    DomainRegistry public immutable domainRegistry;
    IResponseProposalVoting public immutable responseProposal;
    IGovernanceParamsVoting public immutable governanceParams;
    IIncidentRegistryVoting public immutable incidentRegistry;

    mapping(uint256 => VotingSession) public sessions;

    mapping(uint256 => mapping(address => bytes32))
        public voteCommitments;

    mapping(uint256 => mapping(address => bool))
        public hasCommitted;

    mapping(uint256 => mapping(address => bool))
        public hasRevealed;

    mapping(uint256 => mapping(uint8 => uint256))
        private voteCounts;

    event VotingStarted(
        uint256 indexed proposalId,
        uint256 commitEnd,
        uint256 revealEnd,
        uint256 eligibleCount
    );

    event VoteCommitted(
        uint256 indexed proposalId,
        address indexed voter,
        bytes32 commitment
    );

    event VoteRevealed(
        uint256 indexed proposalId,
        address indexed voter,
        VoteChoice choice
    );

    event VotingFinalized(uint256 indexed proposalId);

    event ResponseDecisionUpdated(address responseDecision);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
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
        address _responseProposal,
        address _governanceParams,
        address _incidentRegistry
    ) {
        require(
            _domainRegistry != address(0),
            "Invalid domain registry"
        );
        require(
            _responseProposal != address(0),
            "Invalid proposal contract"
        );
        require(
            _governanceParams != address(0),
            "Invalid governance contract"
        );
        require(
            _incidentRegistry != address(0),
            "Invalid incident registry"
        );

        domainRegistry = DomainRegistry(_domainRegistry);

        responseProposal =
            IResponseProposalVoting(_responseProposal);

        governanceParams =
            IGovernanceParamsVoting(_governanceParams);

        incidentRegistry =
            IIncidentRegistryVoting(_incidentRegistry);

        admin = msg.sender;
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

    // Start voting and snapshot governance parameters.
    function startVoting(
        uint256 proposalId
    ) external {
        require(
            responseProposal.isEligibleVoter(
                proposalId,
                msg.sender
            ),
            "Not eligible voter"
        );

        VotingSession storage session = sessions[proposalId];

        require(!session.started, "Voting already started");

        (
            bytes32 incidentId,
            ,
            ,
            ,
            ,
            uint256 createdAt,
            uint256 votingDeadline,
            uint8 status
        ) = responseProposal.proposals(proposalId);

        require(createdAt != 0, "Proposal not found");
        require(status == 0, "Proposal not pending");
        require(
            block.timestamp < votingDeadline,
            "Proposal voting deadline passed"
        );

        uint256 commitWindow =
            governanceParams.commitWindow();

        uint256 revealWindow =
            governanceParams.revealWindow();

        require(
            commitWindow > 0 && revealWindow > 0,
            "Invalid voting windows"
        );

        require(
            commitWindow + revealWindow <=
                votingDeadline - block.timestamp,
            "Voting windows exceed deadline"
        );

        address[] memory voters =
            responseProposal.getEligibleVoters(proposalId);

        require(voters.length > 0, "No eligible voters");

        session.started = true;
        session.commitEnd = block.timestamp + commitWindow;
        session.revealEnd =
            session.commitEnd + revealWindow;

        session.eligibleCount = voters.length;

        session.quarantineThreshold =
            governanceParams.quarantineThreshold();

        session.revokeThreshold =
            governanceParams.revokeThreshold();

        session.patchThreshold =
            governanceParams.patchThreshold();

        session.quorumBasisPoints =
            governanceParams.quorumBasisPoints();

        incidentRegistry.startVoting(incidentId);

        emit VotingStarted(
            proposalId,
            session.commitEnd,
            session.revealEnd,
            session.eligibleCount
        );
    }

    // Submit a hidden vote commitment.
    function commitVote(
        uint256 proposalId,
        bytes32 commitment
    ) external {
        VotingSession storage session = sessions[proposalId];

        require(session.started, "Voting not started");
        require(!session.finalized, "Voting finalized");

        require(
            responseProposal.isEligibleVoter(
                proposalId,
                msg.sender
            ),
            "Not eligible voter"
        );

        require(
            block.timestamp < session.commitEnd,
            "Commit phase ended"
        );

        require(commitment != bytes32(0), "Invalid commitment");

        require(
            !hasCommitted[proposalId][msg.sender],
            "Already committed"
        );

        hasCommitted[proposalId][msg.sender] = true;

        voteCommitments[proposalId][msg.sender] = commitment;

        emit VoteCommitted(
            proposalId,
            msg.sender,
            commitment
        );
    }

    // Reveal the vote after the commitment phase.
    function revealVote(
        uint256 proposalId,
        VoteChoice choice,
        bytes32 salt
    ) external {
        VotingSession storage session = sessions[proposalId];

        require(session.started, "Voting not started");
        require(!session.finalized, "Voting finalized");

        require(
            block.timestamp >= session.commitEnd,
            "Reveal phase not started"
        );

        require(
            block.timestamp < session.revealEnd,
            "Reveal phase ended"
        );

        require(
            responseProposal.isEligibleVoter(
                proposalId,
                msg.sender
            ),
            "Not eligible voter"
        );

        require(
            hasCommitted[proposalId][msg.sender],
            "No vote commitment"
        );

        require(
            !hasRevealed[proposalId][msg.sender],
            "Already revealed"
        );

        bytes32 expectedCommitment = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                proposalId,
                msg.sender,
                uint8(choice),
                salt
            )
        );

        require(
            voteCommitments[proposalId][msg.sender] ==
                expectedCommitment,
            "Invalid vote reveal"
        );

        hasRevealed[proposalId][msg.sender] = true;

        voteCounts[proposalId][uint8(choice)]++;

        session.revealedCount++;

        emit VoteRevealed(
            proposalId,
            msg.sender,
            choice
        );
    }

    // Finalize voting after the reveal phase.
    function finalizeVoting(
        uint256 proposalId
    ) external {
        VotingSession storage session = sessions[proposalId];

        require(session.started, "Voting not started");
        require(!session.finalized, "Voting finalized");

        require(
            block.timestamp >= session.revealEnd,
            "Reveal phase not ended"
        );

        require(
            responseDecision != address(0),
            "Decision contract not set"
        );

        session.finalized = true;

        IResponseDecisionVoting(responseDecision)
            .finalizeDecision(proposalId);

        emit VotingFinalized(proposalId);
    }

    // Generate the commitment off-chain or use this helper.
    function computeCommitment(
        uint256 proposalId,
        address voter,
        VoteChoice choice,
        bytes32 salt
    ) external view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                proposalId,
                voter,
                uint8(choice),
                salt
            )
        );
    }

    function getVoteCount(
        uint256 proposalId,
        VoteChoice choice
    ) external view returns (uint256) {
        return voteCounts[proposalId][uint8(choice)];
    }

    function getVotingData(
        uint256 proposalId
    )
        external
        view
        returns (
            bool started,
            bool finalized,
            uint256 commitEnd,
            uint256 revealEnd,
            uint256 eligibleCount,
            uint256 revealedCount,
            uint256 quarantineThreshold,
            uint256 revokeThreshold,
            uint256 patchThreshold,
            uint256 quorumBasisPoints
        )
    {
        VotingSession storage session = sessions[proposalId];

        return (
            session.started,
            session.finalized,
            session.commitEnd,
            session.revealEnd,
            session.eligibleCount,
            session.revealedCount,
            session.quarantineThreshold,
            session.revokeThreshold,
            session.patchThreshold,
            session.quorumBasisPoints
        );
    }
}
