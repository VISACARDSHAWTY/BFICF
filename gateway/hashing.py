import json
from web3 import Web3


def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def generate_commitment(data):
    encoded = canonical_json(data)
    return Web3.keccak(encoded).hex()


if __name__ == "__main__":
    incident = {
        "incident_id": "INC-001",
        "domain": "EDGE",
        "type": "CYBER",
        "severity": 3
    }

    print("Incident commitment:", generate_commitment(incident))