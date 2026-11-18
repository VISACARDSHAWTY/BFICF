import json
from web3 import Web3


def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def commitment_bytes(data, domain=None, salt=None):
    payload = canonical_json(data)
    if domain is not None:
        payload = domain.encode("utf-8") + b"\x00" + payload
    if salt is not None:
        payload = payload + b"\x00" + bytes(salt)
    return bytes(Web3.keccak(payload))


def generate_commitment(data, domain=None, salt=None):
    return Web3.to_hex(commitment_bytes(data, domain, salt))


if __name__ == "__main__":
    incident = {"incident_id": "INC-001", "domain": "EDGE", "type": "CYBER", "severity": 3}
    print("Incident commitment:", generate_commitment(incident))
