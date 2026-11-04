// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "./DomainRegistry.sol";

interface IIncidentRegistryProposal {
    function stateOf(bytes32 incidentId) external view returns (uint8);
    function markResponseProposed(bytes32 incidentId) external;
    function escalateIncident(bytes32 incidentId) external;
}

interface ICorrelationDecisionProposal {
    function hasCorrelation(bytes32 incidentId) external view returns (bool);
    function isAffectedDomain(bytes32 incidentId, address domain) external view returns (bool);
    function getAffectedDomains(bytes32 incidentId) external view returns (address[] memory);
    function getConfidence(bytes32 incidentId) external view returns (uint8);
}

interface IEvidenceCommitmentProposal {
    function incidentHasEvidence(bytes32 incidentId) external view returns (bool);
}

/**
 * @title ResponseProposal
 * @dev A response proposal for a CORRELATED incident.
 *
 *  - Eligible voters are ALL currently-active affected domains (derived on-chain from the
 *    correlation result). The proposer can no longer hand-pick the electorate.
 *  - The proposer must itself be an affected domain.
 *  - At least one evidence commitment must exist for the incident.
 *  - actions: at least one primary action (QUARANTINE/PATCH/REVOKE/MONITOR); BLOCK_TRAFFIC is
 *    an additional action only. Voters choose the primary response; the winning primary
 *    action (plus the proposal's additional actions) is what may be executed.
 *  - A proposal can only EXPIRE if voting never started, and expiry escalates the incident
 *    instead of leaving it stuck.
 */
contract ResponseProposal {
    enum ResponseAction { QUARANTINE, PATCH, REVOKE, BLOCK_TRAFFIC, MONITOR, NO_ACTION }

    enum ProposalStatus { PENDING, APPROVED, REJECTED, EXPIRED }

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
    uint256 public constant MAX_ACTIONS = 6;

    uint256 public nextProposalId = 1;
    uint8 public minimumConfidenceClass;

    address public responseDecision;
    address public votingContract;

    DomainRegistry public immutable domainRegistry;
    IIncidentRegistryProposal public immutable incidentRegistry;
    ICorrelationDecisionProposal public immutable correlationDecision;
    IEvidenceCommitmentProposal public immutable evidenceCommitment;

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => ResponseAction[]) private proposalActions;
    mapping(uint256 => mapping(uint8 => bool)) private _hasAction;
    mapping(uint256 => address[]) private eligibleVoters;
    mapping(uint256 => mapping(address => bool)) public isEligibleVoter;
    mapping(uint256 => bool) public votingStarted;

    event ProposalCreated(
        uint256 indexed proposalId,
        bytes32 indexed incidentId,
        address indexed proposer,
        address targetDomain,
        bytes32 targetResourceId,
        uint256 votingDeadline
    );
    event ProposalActionAdded(uint256 indexed proposalId, ResponseAction action);
    event EligibleVoterAdded(uint256 indexed proposalId, address indexed voter);
    event ProposalExpired(uint256 indexed proposalId);
    event MinimumConfidenceUpdated(uint8 newMinimum);
    event ResponseDecisionUpdated(address responseDecision);
    event VotingContractUpdated(address votingContract);
    event ProposalFinalized(uint256 indexed proposalId, ProposalStatus status);

    modifier onlySecAuth() {
        require(domainRegistry.isSecurityAuthority(msg.sender), "Not Security Authority");
        _;
    }

    modifier onlyActiveDomain() {
        require(domainRegistry.isActiveDomain(msg.sender), "Not an active domain");
        _;
    }

    modifier onlyResponseDecision() {
        require(msg.sender == responseDecision && responseDecision != address(0), "Not decision contract");
        _;
    }

    modifier onlyVotingContract() {
        require(msg.sender == votingContract && votingContract != address(0), "Not voting contract");
        _;
    }

    constructor(
        address _domainRegistry,
        address _incidentRegistry,
        address _correlationDecision,
        address _evidenceCommitment,
        uint8 _minimumConfidenceClass
    ) {
        require(_domainRegistry != address(0), "Invalid domain registry");
        require(_incidentRegistry != address(0), "Invalid incident registry");
        require(_correlationDecision != address(0), "Invalid correlation contract");
        require(_evidenceCommitment != address(0), "Invalid evidence contract");
        require(_minimumConfidenceClass <= 3, "Invalid confidence class");

        domainRegistry = DomainRegistry(_domainRegistry);
        incidentRegistry = IIncidentRegistryProposal(_incidentRegistry);
        correlationDecision = ICorrelationDecisionProposal(_correlationDecision);
        evidenceCommitment = IEvidenceCommitmentProposal(_evidenceCommitment);
        minimumConfidenceClass = _minimumConfidenceClass;
    }

    // ---------------- configuration (Security Authority) ----------------

    function setMinimumConfidenceClass(uint8 newMinimum) external onlySecAuth {
        require(newMinimum <= 3, "Invalid confidence class");
        minimumConfidenceClass = newMinimum;
        emit MinimumConfidenceUpdated(newMinimum);
    }

    /// @dev Write-once wiring.
    function setResponseDecision(address _responseDecision) external onlySecAuth {
        require(responseDecision == address(0), "Decision already set");
        require(_responseDecision != address(0), "Invalid decision address");
        responseDecision = _responseDecision;
        emit ResponseDecisionUpdated(_responseDecision);
    }

    /// @dev Write-once wiring.
    function setVotingContract(address _votingContract) external onlySecAuth {
        require(votingContract == address(0), "Voting already set");
        require(_votingContract != address(0), "Invalid voting address");
        votingContract = _votingContract;
        emit VotingContractUpdated(_votingContract);
    }

    // ---------------- proposal creation ----------------

    function createProposal(
        bytes32 incidentId,
        address targetDomain,
        bytes32 targetResourceId,
        ResponseAction[] calldata actions,
        bytes32 detailsHash,
        uint256 votingDuration
    ) external onlyActiveDomain returns (uint256 proposalId) {
        require(targetResourceId != bytes32(0), "Invalid target resource");
        require(detailsHash != bytes32(0), "Invalid details hash");
        require(votingDuration >= MIN_VOTING_PERIOD, "Voting period too short");
        require(votingDuration <= MAX_VOTING_PERIOD, "Voting period too long");

        _checkIncident(incidentId, targetDomain);
        _checkActions(actions);

        proposalId = nextProposalId++;
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

        _storeActions(proposalId, actions);
        _storeVoters(proposalId, incidentId);

        emit ProposalCreated(proposalId, incidentId, msg.sender, targetDomain, targetResourceId, deadline);

        // CORRELATED -> RESPONSE_PROPOSED
        incidentRegistry.markResponseProposed(incidentId);
    }

    function _checkIncident(bytes32 incidentId, address targetDomain) internal view {
        require(targetDomain != address(0), "Invalid target domain");
        require(domainRegistry.isActiveDomain(targetDomain), "Target domain not active");
        require(correlationDecision.hasCorrelation(incidentId), "Incident not correlated");
        require(incidentRegistry.stateOf(incidentId) == 1, "Incident not CORRELATED");
        require(correlationDecision.isAffectedDomain(incidentId, targetDomain), "Target domain not affected");
        require(correlationDecision.isAffectedDomain(incidentId, msg.sender), "Proposer not affected");
        require(evidenceCommitment.incidentHasEvidence(incidentId), "No evidence committed");
        require(
            correlationDecision.getConfidence(incidentId) >= minimumConfidenceClass,
            "Insufficient correlation confidence"
        );
    }

    function _checkActions(ResponseAction[] calldata actions) internal pure {
        require(actions.length > 0, "No response actions");
        require(actions.length <= MAX_ACTIONS, "Too many actions");

        bool hasPrimary;
        for (uint256 i = 0; i < actions.length; i++) {
            require(actions[i] != ResponseAction.NO_ACTION, "NO_ACTION cannot be proposed");
            if (actions[i] != ResponseAction.BLOCK_TRAFFIC) hasPrimary = true;

            for (uint256 j = 0; j < i; j++) {
                require(actions[i] != actions[j], "Duplicate response action");
            }
        }
        require(hasPrimary, "Need a primary action");
    }

    function _storeActions(uint256 proposalId, ResponseAction[] calldata actions) internal {
        for (uint256 i = 0; i < actions.length; i++) {
            proposalActions[proposalId].push(actions[i]);
            _hasAction[proposalId][uint8(actions[i])] = true;
            emit ProposalActionAdded(proposalId, actions[i]);
        }
    }

    function _storeVoters(uint256 proposalId, bytes32 incidentId) internal {
        address[] memory affectedList = correlationDecision.getAffectedDomains(incidentId);
        uint256 count;

        for (uint256 i = 0; i < affectedList.length; i++) {
            address voter = affectedList[i];
            if (!domainRegistry.isActiveDomain(voter)) continue;

            eligibleVoters[proposalId].push(voter);
            isEligibleVoter[proposalId][voter] = true;
            count++;
            emit EligibleVoterAdded(proposalId, voter);
        }

        require(count > 0, "No eligible voters");
    }

    // ---------------- voting / decision hooks ----------------

    function markVotingStarted(uint256 proposalId) external onlyVotingContract {
        require(proposals[proposalId].createdAt != 0, "Proposal not found");
        votingStarted[proposalId] = true;
    }

    function finalizeProposal(uint256 proposalId, bool approved) external onlyResponseDecision {
        Proposal storage proposal = proposals[proposalId];

        require(proposal.createdAt != 0, "Proposal not found");
        require(proposal.status == ProposalStatus.PENDING, "Proposal not pending");

        proposal.status = approved ? ProposalStatus.APPROVED : ProposalStatus.REJECTED;

        emit ProposalFinalized(proposalId, proposal.status);
    }

    /**
     * @dev Anyone may expire a proposal whose voting never started before the deadline.
     *      Once voting has started it can only be closed by FederatedVoting.finalizeVoting,
     *      which removes the expire-vs-finalize race. Expiry escalates the incident.
     */
    function expireProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(proposal.createdAt != 0, "Proposal not found");
        require(proposal.status == ProposalStatus.PENDING, "Proposal not pending");
        require(block.timestamp >= proposal.votingDeadline, "Voting period not ended");
        require(!votingStarted[proposalId], "Voting started");

        proposal.status = ProposalStatus.EXPIRED;

        emit ProposalExpired(proposalId);

        // RESPONSE_PROPOSED -> ESCALATED
        incidentRegistry.escalateIncident(proposal.incidentId);
    }

    // ---------------- views ----------------

    function hasAction(uint256 proposalId, uint8 action) external view returns (bool) {
        return _hasAction[proposalId][action];
    }

    function getActions(uint256 proposalId) external view returns (ResponseAction[] memory) {
        require(proposals[proposalId].createdAt != 0, "Proposal not found");
        return proposalActions[proposalId];
    }

    function getEligibleVoters(uint256 proposalId) external view returns (address[] memory) {
        require(proposals[proposalId].createdAt != 0, "Proposal not found");
        return eligibleVoters[proposalId];
    }

    function isVotingOpen(uint256 proposalId) public view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return proposal.createdAt != 0 &&
               proposal.status == ProposalStatus.PENDING &&
               block.timestamp < proposal.votingDeadline;
    }
}
