from gateway.utils import to_hex

DOMAIN_TYPES = ["OEM", "CLOUD", "EDGE", "USER", "SECAUTH"]
DOMAIN_STATUS = ["ACTIVE", "SUSPENDED", "REMOVED"]


def get_domain(client, domain):
    address = client.resolve_domain_address(domain)
    d = client.get_contract("DomainRegistry").functions.domains(address).call()
    if d[5] == 0:
        raise ValueError(f"Domain not registered: {domain}")
    return {
        "address": address, "name": d[0], "type": DOMAIN_TYPES[d[1]], "status": DOMAIN_STATUS[d[2]],
        "validator": d[3], "public_key": to_hex(d[4]), "registered_at": d[5],
    }


def is_active_domain(client, domain=None):
    address = client.address if domain is None else client.resolve_domain_address(domain)
    return client.get_contract("DomainRegistry").functions.isActiveDomain(address).call()


def is_correlator(client, account=None):
    address = client.address if account is None else client.resolve_domain_address(account)
    return client.get_contract("DomainRegistry").functions.isCorrelator(address).call()


def is_security_authority(client, account=None):
    address = client.address if account is None else client.resolve_domain_address(account)
    return client.get_contract("DomainRegistry").functions.isSecurityAuthority(address).call()


def get_governance_params(client):
    g = client.get_contract("GovernanceParams").functions
    return {
        "quarantine_threshold_bps": g.quarantineThreshold().call(),
        "revoke_threshold_bps": g.revokeThreshold().call(),
        "patch_threshold_bps": g.patchThreshold().call(),
        "quorum_bps": g.quorumBasisPoints().call(),
        "correlation_quorum_bps": g.correlationQuorumBps().call(),
        "commit_window_seconds": g.commitWindow().call(),
        "reveal_window_seconds": g.revealWindow().call(),
    }
