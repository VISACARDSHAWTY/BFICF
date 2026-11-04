// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface IFederatedVotingDecision {
    struct VotingSession {
        bool started;
        bool finalized;
        uint256 commitEnd;
        uint256 revealEnd;
        uint256 eligibleCount;
        uint256 revealedCount;
        uint256 quarantineThreshold;
        uint256 revokeThreshold;
        uint256 patchThreshold;
        uint256 quorumBasisPoints;
    }

    function getSession(uint256 proposalId) external view returns (VotingSession memory);
    function getVoteCounts(uint256 proposalId) external view returns (uint256[5] memory);
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

    function finalizeProposal(uint256 proposalId, bool approved) external;
}

interface IIncidentRegistryDecision {
    function finalizeIncidentDecision(bytes32 incidentId, bool approved) external;
    function escalateIncident(bytes32 incidentId) external;
}

/**
 * @title ResponseDecision
 * @dev Applies the governance rule F(V_1..V_n) to a finished vote.
 *
 *  Outcomes:
 *   QUARANTINE / REVOKE / PATCH   threshold reached  -> proposal APPROVED, incident APPROVED
 *                                 (ties: higher vote count wins, then QUARANTINE > REVOKE > PATCH)
 *   MONITOR                       no threshold reached and MONITOR >= NO_ACTION votes -> APPROVED
 *   NO_ACTION                     no threshold reached and NO_ACTION > MONITOR votes
 *                                 -> proposal REJECTED, incident CLOSED (explicit federation decision)
 *   NO_QUORUM                     too few reveals -> proposal REJECTED, incident ESCALATED
 *                                 (an un-decided incident is never silently closed)
 */
contract ResponseDecision {
    enum DecisionOutcome { QUARANTINE, PATCH, REVOKE, MONITOR, NO_ACTION, NO_QUORUM }

    struct Decision {
        DecisionOutcome outcome;
        uint256 validVotes;
        uint256 eligibleVoters;
        bool quorumReached;
        uint256 timestamp;
        bool finalized;
    }

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
        bool quorumReached,
        uint256[5] tally
    );

    constructor(address _federatedVoting, address _responseProposal, address _incidentRegistry) {
        require(_federatedVoting != address(0), "Invalid voting address");
        require(_responseProposal != address(0), "Invalid proposal address");
        require(_incidentRegistry != address(0), "Invalid incident registry");

        federatedVoting = IFederatedVotingDecision(_federatedVoting);
        responseProposal = IResponseProposalDecision(_responseProposal);
        incidentRegistry = IIncidentRegistryDecision(_incidentRegistry);
    }

    function finalizeDecision(uint256 proposalId) external {
        require(msg.sender == address(federatedVoting), "Not voting contract");
        require(!decisions[proposalId].finalized, "Decision already finalized");

        IFederatedVotingDecision.VotingSession memory s = federatedVoting.getSession(proposalId);

        require(s.started, "Voting not started");
        require(s.finalized, "Voting not finalized");
        require(s.eligibleCount > 0, "No eligible voters");
        require(
            s.quarantineThreshold <= 10000 && s.revokeThreshold <= 10000 &&
            s.patchThreshold <= 10000 && s.quorumBasisPoints <= 10000,
            "Invalid governance parameters"
        );

        bytes32 incidentId = _requirePendingProposal(proposalId);
        uint256[5] memory tally = federatedVoting.getVoteCounts(proposalId);

        (DecisionOutcome outcome, bool quorumReached) = _evaluate(s, tally);

        decisions[proposalId] = Decision({
            outcome: outcome,
            validVotes: s.revealedCount,
            eligibleVoters: s.eligibleCount,
            quorumReached: quorumReached,
            timestamp: block.timestamp,
            finalized: true
        });

        _apply(proposalId, incidentId, outcome);

        emit DecisionFinalized(
            proposalId, incidentId, outcome, s.revealedCount, s.eligibleCount, quorumReached, tally
        );
    }

    function _requirePendingProposal(uint256 proposalId) internal view returns (bytes32 incidentId) {
        uint256 createdAt;
        uint8 status;
        (incidentId, , , , , createdAt, , status) = responseProposal.proposals(proposalId);

        require(createdAt != 0, "Proposal not found");
        require(status == 0, "Proposal not pending");
    }

    function _apply(uint256 proposalId, bytes32 incidentId, DecisionOutcome outcome) internal {
        if (outcome == DecisionOutcome.NO_QUORUM) {
            responseProposal.finalizeProposal(proposalId, false);
            incidentRegistry.escalateIncident(incidentId);        // VOTING -> ESCALATED
        } else if (outcome == DecisionOutcome.NO_ACTION) {
            responseProposal.finalizeProposal(proposalId, false);
            incidentRegistry.finalizeIncidentDecision(incidentId, false); // VOTING -> CLOSED
        } else {
            responseProposal.finalizeProposal(proposalId, true);
            incidentRegistry.finalizeIncidentDecision(incidentId, true);  // VOTING -> APPROVED
        }
    }

    function _evaluate(
        IFederatedVotingDecision.VotingSession memory s,
        uint256[5] memory votes
    ) internal pure returns (DecisionOutcome outcome, bool quorumReached) {
        uint256 valid = s.revealedCount;

        // valid > 0 guard: with zero reveals no outcome may ever pass a threshold.
        quorumReached = valid > 0 && valid * 10000 >= s.eligibleCount * s.quorumBasisPoints;
        if (!quorumReached) {
            return (DecisionOutcome.NO_QUORUM, false);
        }

        bool found;
        uint256 best;

        // QUARANTINE has first priority in a tie.
        if (votes[0] * 10000 >= valid * s.quarantineThreshold) {
            found = true;
            best = votes[0];
            outcome = DecisionOutcome.QUARANTINE;
        }
        // REVOKE second.
        if (votes[2] * 10000 >= valid * s.revokeThreshold && votes[2] > best) {
            found = true;
            best = votes[2];
            outcome = DecisionOutcome.REVOKE;
        }
        // PATCH third.
        if (votes[1] * 10000 >= valid * s.patchThreshold && votes[1] > best) {
            found = true;
            outcome = DecisionOutcome.PATCH;
        }

        if (!found) {
            outcome = votes[4] > votes[3] ? DecisionOutcome.NO_ACTION : DecisionOutcome.MONITOR;
        }
    }

    function getDecision(uint256 proposalId) external view returns (Decision memory) {
        require(decisions[proposalId].finalized, "Decision not finalized");
        return decisions[proposalId];
    }
}
