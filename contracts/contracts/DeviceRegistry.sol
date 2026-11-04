// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

interface IDomainRegistry {
    function isActiveDomain(address account) external view returns (bool);
    function isSecurityAuthority(address account) external view returns (bool);
}

interface IResponseDecisionDevice {
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

interface IResponseProposalDevice {
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

/**
 * @title DeviceRegistry
 * @dev Device lifecycle: ACTIVE -> QUARANTINED -> RECOVERING -> ACTIVE | REVOKED.
 *
 *  - quarantineDevice: the owning domain (local, immediate safety response) or the Security Authority.
 *  - applyDecision:    binds device state to a federation decision. If the proposal's target
 *                      resource is this device and the decision is QUARANTINE / REVOKE, any active
 *                      domain can apply it, so federation outcomes are enforceable on-chain.
 *  - revokeDevice:     Security Authority break-glass.
 */
contract DeviceRegistry {
    enum DeviceState { ACTIVE, QUARANTINED, RECOVERING, REVOKED }

    struct Device {
        bytes32 deviceId;
        address owningDomain;
        bytes32 metadataHash;
        uint256 registeredAt;
        DeviceState state;
    }

    IDomainRegistry public immutable domainRegistry;

    address public recoveryContract;
    address public responseDecision;
    address public responseProposal;

    mapping(bytes32 => Device) public devices;
    mapping(bytes32 => bool) public deviceExists;

    event DeviceRegistered(bytes32 indexed deviceId, address indexed owningDomain, bytes32 metadataHash, uint256 timestamp);
    event DeviceQuarantined(bytes32 indexed deviceId, address indexed owningDomain, bytes32 reasonHash, uint256 timestamp);
    event DeviceStateChanged(bytes32 indexed deviceId, DeviceState previousState, DeviceState newState, uint256 timestamp);
    event DecisionApplied(bytes32 indexed deviceId, uint256 indexed proposalId, uint8 outcome);
    event RecoveryContractUpdated(address indexed previousContract, address indexed newContract);
    event GovernanceContractsUpdated(address responseDecision, address responseProposal);

    modifier onlySecAuth() {
        require(domainRegistry.isSecurityAuthority(msg.sender), "DeviceRegistry: not security authority");
        _;
    }

    modifier onlyRecoveryContract() {
        require(
            msg.sender == recoveryContract && recoveryContract != address(0),
            "DeviceRegistry: not recovery contract"
        );
        _;
    }

    constructor(address _domainRegistry) {
        require(_domainRegistry != address(0), "DeviceRegistry: invalid domain registry");
        domainRegistry = IDomainRegistry(_domainRegistry);
    }

    /// @dev Write-once wiring.
    function setRecoveryContract(address _recoveryContract) external onlySecAuth {
        require(recoveryContract == address(0), "DeviceRegistry: recovery already set");
        require(_recoveryContract != address(0), "DeviceRegistry: invalid recovery contract");

        recoveryContract = _recoveryContract;
        emit RecoveryContractUpdated(address(0), _recoveryContract);
    }

    /// @dev Write-once wiring.
    function setGovernanceContracts(address _responseDecision, address _responseProposal) external onlySecAuth {
        require(responseDecision == address(0), "DeviceRegistry: governance already set");
        require(_responseDecision != address(0) && _responseProposal != address(0), "DeviceRegistry: invalid governance");

        responseDecision = _responseDecision;
        responseProposal = _responseProposal;
        emit GovernanceContractsUpdated(_responseDecision, _responseProposal);
    }

    function registerDevice(bytes32 deviceId, bytes32 metadataHash) external {
        require(domainRegistry.isActiveDomain(msg.sender), "DeviceRegistry: inactive domain");
        require(deviceId != bytes32(0), "DeviceRegistry: invalid device ID");
        require(!deviceExists[deviceId], "DeviceRegistry: device already registered");

        devices[deviceId] = Device({
            deviceId: deviceId,
            owningDomain: msg.sender,
            metadataHash: metadataHash,
            registeredAt: block.timestamp,
            state: DeviceState.ACTIVE
        });
        deviceExists[deviceId] = true;

        emit DeviceRegistered(deviceId, msg.sender, metadataHash, block.timestamp);
    }

    // The owning domain or the Security Authority can quarantine a device.
    function quarantineDevice(bytes32 deviceId, bytes32 reasonHash) external {
        require(deviceExists[deviceId], "DeviceRegistry: device not found");

        Device storage device = devices[deviceId];

        bool isOwner = msg.sender == device.owningDomain && domainRegistry.isActiveDomain(msg.sender);
        require(isOwner || domainRegistry.isSecurityAuthority(msg.sender), "DeviceRegistry: unauthorized caller");

        _quarantine(device, reasonHash);
    }

    /// @dev Enforce a finalized federation decision (QUARANTINE or REVOKE) on its target device.
    function applyDecision(bytes32 deviceId, uint256 proposalId) external {
        require(
            domainRegistry.isActiveDomain(msg.sender) || domainRegistry.isSecurityAuthority(msg.sender),
            "DeviceRegistry: unauthorized caller"
        );
        require(responseDecision != address(0), "DeviceRegistry: governance not set");
        require(deviceExists[deviceId], "DeviceRegistry: device not found");

        (uint8 outcome, , , , , bool finalized) = IResponseDecisionDevice(responseDecision).decisions(proposalId);
        require(finalized, "DeviceRegistry: decision not finalized");

        (, , , bytes32 target, , , , ) = IResponseProposalDevice(responseProposal).proposals(proposalId);
        require(target == deviceId, "DeviceRegistry: proposal targets other resource");

        Device storage device = devices[deviceId];

        if (outcome == 0) {
            _quarantine(device, keccak256(abi.encode("DECISION", proposalId)));
        } else if (outcome == 2) {
            require(device.state != DeviceState.REVOKED, "DeviceRegistry: already revoked");
            _setState(device, DeviceState.REVOKED);
        } else {
            revert("DeviceRegistry: outcome not applicable");
        }

        emit DecisionApplied(deviceId, proposalId, outcome);
    }

    /// @dev Security Authority break-glass revocation.
    function revokeDevice(bytes32 deviceId) external onlySecAuth {
        require(deviceExists[deviceId], "DeviceRegistry: device not found");
        Device storage device = devices[deviceId];
        require(device.state != DeviceState.REVOKED, "DeviceRegistry: already revoked");
        _setState(device, DeviceState.REVOKED);
    }

    // Called by DeviceRecovery when recovery validation is approved.
    function startRecovery(bytes32 deviceId) external onlyRecoveryContract {
        require(deviceExists[deviceId], "DeviceRegistry: device not found");

        Device storage device = devices[deviceId];
        require(device.state == DeviceState.QUARANTINED, "DeviceRegistry: device not quarantined");

        _setState(device, DeviceState.RECOVERING);
    }

    // Called by DeviceRecovery after final recovery evaluation.
    function finalizeRecovery(bytes32 deviceId, bool successful) external onlyRecoveryContract {
        require(deviceExists[deviceId], "DeviceRegistry: device not found");

        Device storage device = devices[deviceId];
        require(device.state == DeviceState.RECOVERING, "DeviceRegistry: device not recovering");

        _setState(device, successful ? DeviceState.ACTIVE : DeviceState.REVOKED);
    }

    function _quarantine(Device storage device, bytes32 reasonHash) internal {
        require(device.state == DeviceState.ACTIVE, "DeviceRegistry: device not active");

        _setState(device, DeviceState.QUARANTINED);
        emit DeviceQuarantined(device.deviceId, device.owningDomain, reasonHash, block.timestamp);
    }

    function _setState(Device storage device, DeviceState newState) internal {
        DeviceState previous = device.state;
        device.state = newState;
        emit DeviceStateChanged(device.deviceId, previous, newState, block.timestamp);
    }

    // ---------------- views ----------------

    function getDevice(bytes32 deviceId) external view returns (Device memory) {
        require(deviceExists[deviceId], "DeviceRegistry: device not found");
        return devices[deviceId];
    }

    function isDeviceActive(bytes32 deviceId) external view returns (bool) {
        return deviceExists[deviceId] && devices[deviceId].state == DeviceState.ACTIVE;
    }

    function isDeviceQuarantined(bytes32 deviceId) external view returns (bool) {
        return deviceExists[deviceId] && devices[deviceId].state == DeviceState.QUARANTINED;
    }

    function isDeviceOwner(bytes32 deviceId, address domain) external view returns (bool) {
        return deviceExists[deviceId] && devices[deviceId].owningDomain == domain;
    }
}
