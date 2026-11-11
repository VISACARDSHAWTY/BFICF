
DOMAINS = {
    "OEM": {
        "port": 8001
    },
    "CLOUD": {
        "port": 8002
    },
    "EDGE": {
        "port": 8003
    },
    "USER": {
        "port": 8004
    },
    "SECAUTH": {
        "port": 8005
    }
}


def get_domain_config(domain: str) -> dict:
    domain = domain.upper()

    if domain not in DOMAINS:
        raise ValueError(f"Unknown domain: {domain}")

    return DOMAINS[domain]
