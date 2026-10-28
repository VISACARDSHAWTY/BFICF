// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title DomainRegistry
 * @dev Manages participating domains, their roles, Ethereum addresses, and active status.
 */
contract DomainRegistry is AccessControl {
    bytes32 public constant SECAUTH_ROLE = keccak256("SECAUTH_ROLE");
    bytes32 public constant DOMAIN_ROLE = keccak256("DOMAIN_ROLE");

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

    // Mapping from domain Ethereum address to its metadata
    mapping(address => DomainInfo) public domains;
    
    // Mapping from domain name string hash to address
    mapping(bytes32 => address) public nameToAddress;

    event DomainRegistered(address indexed account, string name, DomainType domainType, bool validatorFlag);
    event DomainUpdated(address indexed account, DomainStatus status, bool validatorFlag);
    event DomainKeyUpdated(address indexed account);

    constructor(address securityAuthority) {
        _grantRole(DEFAULT_ADMIN_ROLE, securityAuthority);
        _grantRole(SECAUTH_ROLE, securityAuthority);
    }

    /**
     * @dev Register a new participating domain into the consortium.
     */
    function registerDomain(
        address account,
        string calldata name,
        DomainType domainType,
        bool _isValidator,
        bytes calldata publicKey
    ) external onlyRole(SECAUTH_ROLE) {
        require(account != address(0), "Invalid address");
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

    /**
     * @dev Update a domain's status or validator flag.
     */
    function updateDomainStatus(address account, DomainStatus status, bool _isValidator) external onlyRole(SECAUTH_ROLE) {
        require(domains[account].registeredAt != 0, "Domain not found");
        domains[account].status = status;
        domains[account].validatorFlag = _isValidator;

        if (status == DomainStatus.REMOVED || status == DomainStatus.SUSPENDED) {
            _revokeRole(DOMAIN_ROLE, account);
        } else if (status == DomainStatus.ACTIVE && !hasRole(DOMAIN_ROLE, account)) {
            _grantRole(DOMAIN_ROLE, account);
        }

        emit DomainUpdated(account, status, _isValidator);
    }

    /**
     * @dev Check if an address represents an active domain.
     */
    function isActiveDomain(address account) external view returns (bool) {
        return domains[account].registeredAt != 0 && domains[account].status == DomainStatus.ACTIVE;
    }

    /**
     * @dev Check if an address is an authorized validator.
     */
    function isValidator(address account) external view returns (bool) {
        return domains[account].registeredAt != 0 && 
               domains[account].status == DomainStatus.ACTIVE && 
               domains[account].validatorFlag;
    }
}