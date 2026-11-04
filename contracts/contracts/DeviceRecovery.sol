// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface IRecoveryDomainRegistry {
    function isActiveDomain(address account) external view returns (bool);
    function isSecurityAuthority(address account) external view returns (bool);
}

interface IRecoveryDeviceRegistry {
    function isDeviceOwner(bytes32 deviceId, address domain) external view returns (bool);
    function isDeviceQuarantined(bytes32 deviceId) external view returns (bool);
    function startRecovery(bytes32 deviceId) external;
    function finalizeRecovery(bytes32 deviceId, bool successful) external;
}

/**
 * @title DeviceRecovery
 * @dev QUARANTINED -> RECOVERING -> ACTIVE | REVOKED with cross-domain validation.
 *
 *  - The owning domain submits remediation / AI-evaluation / attestation / evidence commitments.
 *  - Other active domains validate; `requiredApprovals` approvals move the device to RECOVERING.
 *  - A validation window prevents a request from blocking a device forever (e.g. when
 *    requiredApprovals can never be reached): anyone can expire it after the window.
 *  - The designated verifier (set by the Security Authority) records the final assessment.
 */
contract DeviceRecovery {
    enum RecoveryStatus { VALIDATING, APPROVED, REJECTED, COMPLETED }

    struct RecoveryRequest {
        uint256 requestId;
        bytes32 deviceId;
        address requestingDomain;

        bytes32 remediationHash;
        bytes32 aiEvaluationHash;
        bytes32 attestationHash;
        bytes32 recoveryEvidenceHash;

        uint256 approvalCount;
        uint256 rejectionCount;
        uint256 requestedAt;
        uint256 expiresAt;

        RecoveryStatus status;

        bool successful;
        bytes32 finalAssessmentHash;
    }

    IRecoveryDomainRegistry public immutable domainRegistry;
    IRecoveryDeviceRegistry public immutable deviceRegistry;

    address public verifier;

    uint256 public requiredApprovals;
    uint256 public validationWindow;
    uint256 public nextRequestId = 1;

    mapping(uint256 => RecoveryRequest) public recoveryRequests;
    mapping(uint256 => mapping(address => bool)) public hasValidated;
    mapping(bytes32 => uint256) public activeRequestByDevice;

    event RecoveryRequested(uint256 indexed requestId, bytes32 indexed deviceId, address indexed requestingDomain, uint256 timestamp);
    event RecoveryValidated(uint256 indexed requestId, address indexed validatingDomain, bool approved, uint256 approvalCount, uint256 rejectionCount);
    event RecoveryApproved(uint256 indexed requestId, bytes32 indexed deviceId, uint256 timestamp);
    event RecoveryRejected(uint256 indexed requestId, bytes32 indexed deviceId, uint256 timestamp);
    event RecoveryExpired(uint256 indexed requestId, bytes32 indexed deviceId, uint256 timestamp);
    event RecoveryFinalized(uint256 indexed requestId, bytes32 indexed deviceId, bool successful, bytes32 finalAssessmentHash, uint256 timestamp);
    event VerifierUpdated(address indexed previousVerifier, address indexed newVerifier);
    event ApprovalThresholdUpdated(uint256 previousThreshold, uint256 newThreshold);
    event ValidationWindowUpdated(uint256 previousWindow, uint256 newWindow);

    modifier onlySecAuth() {
        require(domainRegistry.isSecurityAuthority(msg.sender), "DeviceRecovery: not security authority");
        _;
    }

    modifier onlyVerifier() {
        require(msg.sender == verifier && verifier != address(0), "DeviceRecovery: not verifier");
        _;
    }

    constructor(
        address _domainRegistry,
        address _deviceRegistry,
        address _verifier,
        uint256 _requiredApprovals,
        uint256 _validationWindow
    ) {
        require(_domainRegistry != address(0), "DeviceRecovery: invalid domain registry");
        require(_deviceRegistry != address(0), "DeviceRecovery: invalid device registry");
        require(_verifier != address(0), "DeviceRecovery: invalid verifier");
        require(_requiredApprovals > 0, "DeviceRecovery: invalid approval threshold");
        require(_validationWindow > 0, "DeviceRecovery: invalid validation window");

        domainRegistry = IRecoveryDomainRegistry(_domainRegistry);
        deviceRegistry = IRecoveryDeviceRegistry(_deviceRegistry);
        verifier = _verifier;
        requiredApprovals = _requiredApprovals;
        validationWindow = _validationWindow;
    }

    function setVerifier(address _verifier) external onlySecAuth {
        require(_verifier != address(0), "DeviceRecovery: invalid verifier");
        address previous = verifier;
        verifier = _verifier;
        emit VerifierUpdated(previous, _verifier);
    }

    function setRequiredApprovals(uint256 _requiredApprovals) external onlySecAuth {
        require(_requiredApprovals > 0, "DeviceRecovery: invalid approval threshold");
        uint256 previous = requiredApprovals;
        requiredApprovals = _requiredApprovals;
        emit ApprovalThresholdUpdated(previous, _requiredApprovals);
    }

    function setValidationWindow(uint256 _window) external onlySecAuth {
        require(_window > 0, "DeviceRecovery: invalid validation window");
        uint256 previous = validationWindow;
        validationWindow = _window;
        emit ValidationWindowUpdated(previous, _window);
    }

    // The owning domain submits a recovery request after remediation and local re-evaluation.
    function submitRecoveryRequest(
        bytes32 deviceId,
        bytes32 remediationHash,
        bytes32 aiEvaluationHash,
        bytes32 attestationHash,
        bytes32 recoveryEvidenceHash
    ) external returns (uint256 requestId) {
        require(domainRegistry.isActiveDomain(msg.sender), "DeviceRecovery: inactive domain");
        require(deviceRegistry.isDeviceOwner(deviceId, msg.sender), "DeviceRecovery: not device owner");
        require(deviceRegistry.isDeviceQuarantined(deviceId), "DeviceRecovery: device not quarantined");
        require(activeRequestByDevice[deviceId] == 0, "DeviceRecovery: active request exists");
        require(remediationHash != bytes32(0), "DeviceRecovery: missing remediation evidence");
        require(aiEvaluationHash != bytes32(0), "DeviceRecovery: missing AI evaluation");
        require(attestationHash != bytes32(0), "DeviceRecovery: missing attestation");
        require(recoveryEvidenceHash != bytes32(0), "DeviceRecovery: missing recovery evidence");

        requestId = nextRequestId++;

        recoveryRequests[requestId] = RecoveryRequest({
            requestId: requestId,
            deviceId: deviceId,
            requestingDomain: msg.sender,
            remediationHash: remediationHash,
            aiEvaluationHash: aiEvaluationHash,
            attestationHash: attestationHash,
            recoveryEvidenceHash: recoveryEvidenceHash,
            approvalCount: 0,
            rejectionCount: 0,
            requestedAt: block.timestamp,
            expiresAt: block.timestamp + validationWindow,
            status: RecoveryStatus.VALIDATING,
            successful: false,
            finalAssessmentHash: bytes32(0)
        });

        activeRequestByDevice[deviceId] = requestId;

        emit RecoveryRequested(requestId, deviceId, msg.sender, block.timestamp);
    }

    // Other active domains validate the evidence. The owning domain cannot validate its own request.
    function validateRecovery(uint256 requestId, bool approved) external {
        require(domainRegistry.isActiveDomain(msg.sender), "DeviceRecovery: inactive domain");

        RecoveryRequest storage request = recoveryRequests[requestId];

        require(request.requestId != 0, "DeviceRecovery: request not found");
        require(request.status == RecoveryStatus.VALIDATING, "DeviceRecovery: request not validating");
        require(block.timestamp < request.expiresAt, "DeviceRecovery: validation window over");
        require(msg.sender != request.requestingDomain, "DeviceRecovery: owner cannot validate");
        require(!hasValidated[requestId][msg.sender], "DeviceRecovery: already validated");

        hasValidated[requestId][msg.sender] = true;

        if (approved) {
            request.approvalCount++;
        } else {
            request.rejectionCount++;
        }

        emit RecoveryValidated(requestId, msg.sender, approved, request.approvalCount, request.rejectionCount);

        if (request.approvalCount >= requiredApprovals) {
            request.status = RecoveryStatus.APPROVED;

            // QUARANTINED -> RECOVERING
            deviceRegistry.startRecovery(request.deviceId);

            emit RecoveryApproved(requestId, request.deviceId, block.timestamp);
        } else if (request.rejectionCount >= requiredApprovals) {
            request.status = RecoveryStatus.REJECTED;
            activeRequestByDevice[request.deviceId] = 0;

            emit RecoveryRejected(requestId, request.deviceId, block.timestamp);
        }
    }

    /// @dev Frees the device for a new request when validation could not complete in time.
    function expireRequest(uint256 requestId) external {
        RecoveryRequest storage request = recoveryRequests[requestId];

        require(request.requestId != 0, "DeviceRecovery: request not found");
        require(request.status == RecoveryStatus.VALIDATING, "DeviceRecovery: request not validating");
        require(block.timestamp >= request.expiresAt, "DeviceRecovery: window not over");

        request.status = RecoveryStatus.REJECTED;
        activeRequestByDevice[request.deviceId] = 0;

        emit RecoveryExpired(requestId, request.deviceId, block.timestamp);
    }

    // The designated verifier submits the final recovery assessment.
    function finalizeRecovery(
        uint256 requestId,
        bool successful,
        bytes32 finalAssessmentHash
    ) external onlyVerifier {
        RecoveryRequest storage request = recoveryRequests[requestId];

        require(request.requestId != 0, "DeviceRecovery: request not found");
        require(request.status == RecoveryStatus.APPROVED, "DeviceRecovery: request not approved");
        require(finalAssessmentHash != bytes32(0), "DeviceRecovery: missing final assessment");

        request.successful = successful;
        request.finalAssessmentHash = finalAssessmentHash;
        request.status = RecoveryStatus.COMPLETED;

        // Successful: RECOVERING -> ACTIVE.  Failed: RECOVERING -> REVOKED.
        deviceRegistry.finalizeRecovery(request.deviceId, successful);

        activeRequestByDevice[request.deviceId] = 0;

        emit RecoveryFinalized(requestId, request.deviceId, successful, finalAssessmentHash, block.timestamp);
    }

    function getRecoveryRequest(uint256 requestId) external view returns (RecoveryRequest memory) {
        require(recoveryRequests[requestId].requestId != 0, "DeviceRecovery: request not found");
        return recoveryRequests[requestId];
    }

    function getActiveRequest(bytes32 deviceId) external view returns (uint256) {
        return activeRequestByDevice[deviceId];
    }
}
