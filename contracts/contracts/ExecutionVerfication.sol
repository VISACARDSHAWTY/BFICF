
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface ICoordinatedExecutionVerification {
    function getAction(uint256 actionId)
        external
        view
        returns (
            uint256 proposalId,
            bytes32 incidentId,
            address responsibleDomain,
            bytes32 actionType,
            bytes32 targetResourceId,
            bytes32 detailsHash,
            bytes32 receiptHash,
            uint256 reportedAt,
            uint8 status
        );

    function markActionVerified(
        uint256 actionId,
        bool successful
    ) external;

    function getPlanProgress(uint256 proposalId)
        external
        view
        returns (
            bytes32 incidentId,
            uint256 totalActions,
            uint256 verifiedActions,
            bool complete
        );
}

interface IIncidentRegistryVerification {
    function markIncidentVerified(bytes32 incidentId) external;
    function closeVerifiedIncident(bytes32 incidentId) external;
}

contract ExecutionVerification {
    address public admin;
    address public verifier;

    ICoordinatedExecutionVerification public immutable executionContract;
    IIncidentRegistryVerification public immutable incidentRegistry;

    mapping(uint256 => bytes32) public verifiedReceiptHashes;

    event VerifierUpdated(address indexed verifier);

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

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyVerifier() {
        require(
            msg.sender == verifier && verifier != address(0),
            "Not authorized verifier"
        );
        _;
    }

    constructor(
        address _executionContract,
        address _incidentRegistry,
        address _verifier
    ) {
        require(
            _executionContract != address(0),
            "Invalid execution contract"
        );

        require(
            _incidentRegistry != address(0),
            "Invalid incident registry"
        );

        require(
            _verifier != address(0),
            "Invalid verifier"
        );

        executionContract =
            ICoordinatedExecutionVerification(_executionContract);

        incidentRegistry =
            IIncidentRegistryVerification(_incidentRegistry);

        admin = msg.sender;
        verifier = _verifier;
    }

    function setVerifier(address _verifier) external onlyAdmin {
        require(_verifier != address(0), "Invalid verifier");

        verifier = _verifier;

        emit VerifierUpdated(_verifier);
    }

    function verifyAction(
        uint256 actionId,
        bool successful
    ) external onlyVerifier {
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

        require(proposalId != 0, "Action not found");
        require(status == 1, "Action not submitted");
        require(receiptHash != bytes32(0), "Receipt not found");
        require(
            verifiedReceiptHashes[actionId] != receiptHash,
            "Receipt already verified"
        );

        verifiedReceiptHashes[actionId] = receiptHash;

        executionContract.markActionVerified(
            actionId,
            successful
        );

        emit ReceiptVerified(
            actionId,
            proposalId,
            incidentId,
            responsibleDomain,
            receiptHash,
            successful,
            block.timestamp
        );

        if (successful) {
            (
                bytes32 planIncidentId,
                uint256 totalActions,
                uint256 verifiedActions,
                bool complete
            ) = executionContract.getPlanProgress(proposalId);

            if (complete) {
                require(
                    planIncidentId == incidentId,
                    "Incident mismatch"
                );

                // EXECUTING -> VERIFIED
                incidentRegistry.markIncidentVerified(incidentId);

                // VERIFIED -> CLOSED
                incidentRegistry.closeVerifiedIncident(incidentId);

                emit IncidentExecutionCompleted(
                    proposalId,
                    incidentId,
                    totalActions,
                    block.timestamp
                );
            }
        }
    }
}
