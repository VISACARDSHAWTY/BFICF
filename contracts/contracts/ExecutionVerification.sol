// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface IDomainRegistryVerification {
    function isActiveDomain(address domain) external view returns (bool);
    function isSecurityAuthority(address account) external view returns (bool);
}

interface ICoordinatedExecutionVerification {
    function getAction(uint256 actionId)
        external
        view
        returns (
            uint256 proposalId,
            bytes32 incidentId,
            address responsibleDomain,
            uint8 actionType,
            bytes32 targetResourceId,
            bytes32 detailsHash,
            bytes32 receiptHash,
            uint256 reportedAt,
            uint8 status
        );

    function markActionVerified(uint256 actionId, bool successful) external;

    function getPlanProgress(uint256 proposalId)
        external
        view
        returns (bytes32 incidentId, uint256 totalActions, uint256 verifiedActions, bool complete);
}

interface IIncidentRegistryVerification {
    function markIncidentVerified(bytes32 incidentId) external;
}

/**
 * @title ExecutionVerification
 * @dev Peer verification of execution receipts.
 *
 *  Receipt hashes reported by the responsible domain are attested by OTHER active domains.
 *  `requiredAttestations` approvals mark the action VERIFIED; the same number of rejections
 *  marks it FAILED (the responsible domain may then re-report with a new receipt).
 *  When every action of a plan is VERIFIED the incident moves EXECUTING -> VERIFIED.
 *  Closing (VERIFIED -> CLOSED) is an explicit step in IncidentRegistry.closeIncident,
 *  carrying a closure-record commitment.
 *
 *  No single verifier account exists any more, so no single party can verify or block a plan.
 *  Note: requiredAttestations must not exceed the number of non-responsible active domains.
 */
contract ExecutionVerification {
    IDomainRegistryVerification public immutable domainRegistry;
    ICoordinatedExecutionVerification public immutable executionContract;
    IIncidentRegistryVerification public immutable incidentRegistry;

    uint256 public requiredAttestations;

    // key = keccak256(actionId, receiptHash): attestations belong to one specific receipt
    mapping(bytes32 => uint256) public approvals;
    mapping(bytes32 => uint256) public rejections;
    mapping(bytes32 => mapping(address => bool)) public hasAttested;

    event RequiredAttestationsUpdated(uint256 required);
    event ActionAttested(uint256 indexed actionId, address indexed attester, bytes32 receiptHash, bool valid);
    event ReceiptVerified(
        uint256 indexed actionId,
        uint256 indexed proposalId,
        bytes32 indexed incidentId,
        address responsibleDomain,
        bytes32 receiptHash,
        bool successful,
        uint256 timestamp
    );
    event IncidentExecutionCompleted(
        uint256 indexed proposalId,
        bytes32 indexed incidentId,
        uint256 totalActions,
        uint256 timestamp
    );

    modifier onlySecAuth() {
        require(domainRegistry.isSecurityAuthority(msg.sender), "Not Security Authority");
        _;
    }

    constructor(
        address _domainRegistry,
        address _executionContract,
        address _incidentRegistry,
        uint256 _requiredAttestations
    ) {
        require(_domainRegistry != address(0), "Invalid domain registry");
        require(_executionContract != address(0), "Invalid execution contract");
        require(_incidentRegistry != address(0), "Invalid incident registry");
        require(_requiredAttestations > 0, "Invalid attestation threshold");

        domainRegistry = IDomainRegistryVerification(_domainRegistry);
        executionContract = ICoordinatedExecutionVerification(_executionContract);
        incidentRegistry = IIncidentRegistryVerification(_incidentRegistry);
        requiredAttestations = _requiredAttestations;
    }

    function setRequiredAttestations(uint256 _required) external onlySecAuth {
        require(_required > 0, "Invalid attestation threshold");
        requiredAttestations = _required;
        emit RequiredAttestationsUpdated(_required);
    }

    function attestAction(uint256 actionId, bool valid) external {
        require(domainRegistry.isActiveDomain(msg.sender), "Not an active domain");

        (
            uint256 proposalId,
            bytes32 incidentId,
            address responsibleDomain,
            ,
            ,
            ,
            bytes32 receiptHash,
            ,
            uint8 status
        ) = executionContract.getAction(actionId);

        require(status == 1, "Action not submitted");
        require(receiptHash != bytes32(0), "Receipt not found");
        require(msg.sender != responsibleDomain, "Responsible domain cannot attest");

        bytes32 key = keccak256(abi.encode(actionId, receiptHash));
        require(!hasAttested[key][msg.sender], "Already attested");
        hasAttested[key][msg.sender] = true;

        if (valid) {
            approvals[key]++;
        } else {
            rejections[key]++;
        }

        emit ActionAttested(actionId, msg.sender, receiptHash, valid);

        if (approvals[key] >= requiredAttestations) {
            executionContract.markActionVerified(actionId, true);
            emit ReceiptVerified(
                actionId, proposalId, incidentId, responsibleDomain, receiptHash, true, block.timestamp
            );
            _checkPlanCompletion(proposalId, incidentId);
        } else if (rejections[key] >= requiredAttestations) {
            executionContract.markActionVerified(actionId, false);
            emit ReceiptVerified(
                actionId, proposalId, incidentId, responsibleDomain, receiptHash, false, block.timestamp
            );
        }
    }

    function _checkPlanCompletion(uint256 proposalId, bytes32 incidentId) internal {
        (bytes32 planIncidentId, uint256 totalActions, , bool complete) =
            executionContract.getPlanProgress(proposalId);

        if (complete) {
            require(planIncidentId == incidentId, "Incident mismatch");

            // EXECUTING -> VERIFIED
            incidentRegistry.markIncidentVerified(incidentId);

            emit IncidentExecutionCompleted(proposalId, incidentId, totalActions, block.timestamp);
        }
    }
}
