
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface IFederatedVotingDecision {
    function getVotingData(uint256 proposalId)
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
        );

    function getVoteCount(
        uint256 proposalId,
        uint8 choice
    ) external view returns (uint256);
}

interface IResponseProposalDecision {
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

    function finalizeProposal(
        uint256 proposalId,
        bool approved
    ) external;
}

interface IIncidentRegistryDecision {
    function finalizeIncidentDecision(
        bytes32 incidentId,
        bool approved
    ) external;
}

contract ResponseDecision {
    enum DecisionOutcome {
        QUARANTINE,
        PATCH,
        REVOKE,
        MONITOR,
        NO_ACTION
    }

    struct Decision {
        DecisionOutcome outcome;
        uint256 validVotes;
        uint256 eligibleVoters;
        bool quorumReached;
        uint256 timestamp;
        bool finalized;
    }

    address public admin;

    IFederatedVotingDecision public immutable federatedVoting;
    IResponseProposalDecision public immutable responseProposal;
    IIncidentRegistryDecision public immutable incidentRegistry;

    mapping(uint256 => Decision) public decisions;

    event DecisionFinalized(
        uint256 indexed proposalId,
        bytes32 indexed incidentId,
        DecisionOutcome outcome,
        uint256 validVotes,
        uint256 eligibleVoters,
        bool quorumReached
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyFederatedVoting() {
        require(
            msg.sender == address(federatedVoting),
            "Not voting contract"
        );
        _;
    }

    constructor(
        address _federatedVoting,
        address _responseProposal,
        address _incidentRegistry
    ) {
        require(
            _federatedVoting != address(0),
            "Invalid voting address"
        );

        require(
            _responseProposal != address(0),
            "Invalid proposal address"
        );

        require(
            _incidentRegistry != address(0),
            "Invalid incident registry"
        );

        federatedVoting =
            IFederatedVotingDecision(_federatedVoting);

        responseProposal =
            IResponseProposalDecision(_responseProposal);

        incidentRegistry =
            IIncidentRegistryDecision(_incidentRegistry);

        admin = msg.sender;
    }

    function finalizeDecision(
        uint256 proposalId
    ) external onlyFederatedVoting {
        require(
            !decisions[proposalId].finalized,
            "Decision already finalized"
        );

        (
            bool started,
            bool votingFinalized,
            ,
            ,
            uint256 eligibleCount,
            uint256 revealedCount,
            uint256 quarantineThreshold,
            uint256 revokeThreshold,
            uint256 patchThreshold,
            uint256 quorumBasisPoints
        ) = federatedVoting.getVotingData(proposalId);

        require(started, "Voting not started");
        require(votingFinalized, "Voting not finalized");
        require(eligibleCount > 0, "No eligible voters");

        require(
            quarantineThreshold <= 10000 &&
            revokeThreshold <= 10000 &&
            patchThreshold <= 10000 &&
            quorumBasisPoints <= 10000,
            "Invalid governance parameters"
        );

        (
            bytes32 incidentId,
            ,
            ,
            ,
            ,
            uint256 createdAt,
            ,
            uint8 proposalStatus
        ) = responseProposal.proposals(proposalId);

        require(createdAt != 0, "Proposal not found");
        require(proposalStatus == 0, "Proposal not pending");

        DecisionOutcome outcome;
        bool quorumReached =
            revealedCount * 10000 >=
            eligibleCount * quorumBasisPoints;

        if (!quorumReached) {
            outcome = DecisionOutcome.NO_ACTION;
        } else {
            outcome = _calculateOutcome(
                proposalId,
                revealedCount,
                quarantineThreshold,
                revokeThreshold,
                patchThreshold
            );
        }

        bool approved =
            outcome != DecisionOutcome.NO_ACTION;

        decisions[proposalId] = Decision({
            outcome: outcome,
            validVotes: revealedCount,
            eligibleVoters: eligibleCount,
            quorumReached: quorumReached,
            timestamp: block.timestamp,
            finalized: true
        });

        // Finalize the proposal.
        responseProposal.finalizeProposal(
            proposalId,
            approved
        );

        // Finalize the corresponding incident.
        incidentRegistry.finalizeIncidentDecision(
            incidentId,
            approved
        );

        emit DecisionFinalized(
            proposalId,
            incidentId,
            outcome,
            revealedCount,
            eligibleCount,
            quorumReached
        );
    }

    function _calculateOutcome(
        uint256 proposalId,
        uint256 validVotes,
        uint256 quarantineThreshold,
        uint256 revokeThreshold,
        uint256 patchThreshold
    ) internal view returns (DecisionOutcome) {
        uint256 quarantineVotes =
            federatedVoting.getVoteCount(proposalId, 0);

        uint256 patchVotes =
            federatedVoting.getVoteCount(proposalId, 1);

        uint256 revokeVotes =
            federatedVoting.getVoteCount(proposalId, 2);

        uint256 bestShare = 0;
        DecisionOutcome bestOutcome = DecisionOutcome.MONITOR;

        // QUARANTINE has first priority in a tie.
        if (
            quarantineVotes * 10000 >=
            validVotes * quarantineThreshold
        ) {
            bestShare = quarantineVotes;
            bestOutcome = DecisionOutcome.QUARANTINE;
        }

        // REVOKE has second priority in a tie.
        if (
            revokeVotes * 10000 >=
            validVotes * revokeThreshold &&
            revokeVotes > bestShare
        ) {
            bestShare = revokeVotes;
            bestOutcome = DecisionOutcome.REVOKE;
        }

        // PATCH has third priority in a tie.
        if (
            patchVotes * 10000 >=
            validVotes * patchThreshold &&
            patchVotes > bestShare
        ) {
            bestOutcome = DecisionOutcome.PATCH;
        }

        return bestOutcome;
    }

    function getDecision(
        uint256 proposalId
    ) external view returns (Decision memory) {
        require(
            decisions[proposalId].finalized,
            "Decision not finalized"
        );

        return decisions[proposalId];
    }
}
