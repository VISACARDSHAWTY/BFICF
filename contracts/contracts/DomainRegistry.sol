// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title DomainRegistry
 * @dev Participating domains, roles, keys and status.
 *
 *  - The Security Authority (SECAUTH_ROLE) is the single administrative root of the
 *    federation. Every other contract resolves "admin" through this registry, so the
 *    Security Authority can be a multisig / governance contract without touching other code.
 *  - validatorFlag is informational metadata. Actual BFT consensus membership is
 *    configured in the blockchain client (e.g. Besu QBFT validator set), not here.
 *  - CORRELATOR_ROLE identifies the federated-correlation / aggregation service that is
 *    allowed to submit correlation results (which affected domains then attest).
 */
contract DomainRegistry is AccessControl {
    bytes32 public constant SECAUTH_ROLE = keccak256("SECAUTH_ROLE");
    bytes32 public constant DOMAIN_ROLE = keccak256("DOMAIN_ROLE");
    bytes32 public constant CORRELATOR_ROLE = keccak256("CORRELATOR_ROLE");

    enum DomainType { OEM, CLOUD, EDGE, USER, SECAUTH }
    enum DomainStatus { ACTIVE, SUSPENDED, REMOVED }

    struct DomainInfo {
        string name;
        DomainType domainType;
        DomainStatus status;
        bool validatorFlag;
        bytes publicKey;
        uint256 registeredAt;
    }

    mapping(address => DomainInfo) public domains;
    mapping(bytes32 => address) public nameToAddress;

    event DomainRegistered(address indexed account, string name, DomainType domainType, bool validatorFlag);
    event DomainUpdated(address indexed account, DomainStatus status, bool validatorFlag);
    event DomainKeyUpdated(address indexed account, bytes32 newKeyHash);
    event CorrelatorUpdated(address indexed account, bool enabled);

    constructor(address securityAuthority) {
        require(securityAuthority != address(0), "Invalid security authority");
        _grantRole(DEFAULT_ADMIN_ROLE, securityAuthority);
        _grantRole(SECAUTH_ROLE, securityAuthority);
    }

    function registerDomain(
        address account,
        string calldata name,
        DomainType domainType,
        bool _isValidator,
        bytes calldata publicKey
    ) external onlyRole(SECAUTH_ROLE) {
        require(account != address(0), "Invalid address");
        require(bytes(name).length > 0, "Empty name");
        require(domains[account].registeredAt == 0, "Domain already registered");
        bytes32 nameHash = keccak256(bytes(name));
        require(nameToAddress[nameHash] == address(0), "Domain name already taken");

        domains[account] = DomainInfo({
            name: name,
            domainType: domainType,
            status: DomainStatus.ACTIVE,
            validatorFlag: _isValidator,
            publicKey: publicKey,
            registeredAt: block.timestamp
        });

        nameToAddress[nameHash] = account;
        _grantRole(DOMAIN_ROLE, account);

        emit DomainRegistered(account, name, domainType, _isValidator);
    }

    /// @dev Suspend / reactivate / remove. REMOVED is permanent.
    function updateDomainStatus(
        address account,
        DomainStatus status,
        bool _isValidator
    ) external onlyRole(SECAUTH_ROLE) {
        require(domains[account].registeredAt != 0, "Domain not found");
        require(domains[account].status != DomainStatus.REMOVED, "Domain removed");

        domains[account].status = status;
        domains[account].validatorFlag = _isValidator;

        if (status == DomainStatus.REMOVED || status == DomainStatus.SUSPENDED) {
            _revokeRole(DOMAIN_ROLE, account);
        } else if (!hasRole(DOMAIN_ROLE, account)) {
            _grantRole(DOMAIN_ROLE, account);
        }

        emit DomainUpdated(account, status, _isValidator);
    }

    function updateDomainKey(address account, bytes calldata newPublicKey)
        external
        onlyRole(SECAUTH_ROLE)
    {
        require(domains[account].registeredAt != 0, "Domain not found");
        require(domains[account].status != DomainStatus.REMOVED, "Domain removed");
        require(newPublicKey.length > 0, "Empty key");

        domains[account].publicKey = newPublicKey;
        emit DomainKeyUpdated(account, keccak256(newPublicKey));
    }

    function setCorrelator(address account, bool enabled) external onlyRole(SECAUTH_ROLE) {
        require(account != address(0), "Invalid address");
        if (enabled) {
            _grantRole(CORRELATOR_ROLE, account);
        } else {
            _revokeRole(CORRELATOR_ROLE, account);
        }
        emit CorrelatorUpdated(account, enabled);
    }

    function isActiveDomain(address account) external view returns (bool) {
        return domains[account].registeredAt != 0 &&
               domains[account].status == DomainStatus.ACTIVE;
    }

    function isValidator(address account) external view returns (bool) {
        return domains[account].registeredAt != 0 &&
               domains[account].status == DomainStatus.ACTIVE &&
               domains[account].validatorFlag;
    }

    function isSecurityAuthority(address account) external view returns (bool) {
        return hasRole(SECAUTH_ROLE, account);
    }

    function isCorrelator(address account) external view returns (bool) {
        return hasRole(CORRELATOR_ROLE, account);
    }
}
