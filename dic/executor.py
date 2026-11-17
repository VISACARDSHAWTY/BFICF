import hashlib
import json
import time
from web3 import Web3

from dic.store import (
    save_execution_action,
    get_execution_action_record,
)
from gateway.client import BlockchainClient
from gateway.execution import get_execution_action, report_execution


RESOURCE_MAP = {
    "0x811e38220fdda6364c6d717f9c38a1f2071ee01ef038eba231d960e2170703fe":
        "EDGE-RESOURCE-003",
}


def execute_edge_action(action_id: int) -> dict:
    client = BlockchainClient("EDGE")
    action_data = get_execution_action(client, action_id)

    if action_data["status"] not in ("PENDING", "FAILED"):
        raise ValueError("Action is not awaiting execution")

    if action_data["action"] not in ("QUARANTINE", "MONITOR"):
        raise ValueError("Unsupported EDGE action")

    resource_id = RESOURCE_MAP.get(
        action_data["target_resource_hash"].lower()
    )

    if resource_id is None:
        raise ValueError("Unknown EDGE resource hash")

    existing = get_execution_action_record(action_id)

    if existing and existing["status"] == "EXECUTED":
        if existing["receipt"]:
            return existing["receipt"]
        raise ValueError("Execution is already recorded but has no receipt")

    timestamp = int(time.time())

    receipt = {
        "action_id": action_id,
        "domain": "EDGE",
        "resource_id": resource_id,
        "action": action_data["action"],
        "status": "EXECUTED",
        "execution_mode": "SIMULATED",
        "timestamp": timestamp,
        "proof": {
            "description": (
                "Simulated resource quarantine"
                if action_data["action"] == "QUARANTINE"
                else "Simulated resource monitoring"
            )
        },
    }

    receipt_json = json.dumps(receipt, sort_keys=True)
    receipt["proof"]["sha256"] = hashlib.sha256(
        receipt_json.encode("utf-8")
    ).hexdigest()

    save_execution_action(
        action_id=action_id,
        domain="EDGE",
        resource_id=resource_id,
        action=action_data["action"],
        status="EXECUTED",
        receipt=receipt,
    )

    return receipt

def execute_cloud_action(action_id: int) -> dict:
    client = BlockchainClient("CLOUD")
    action_data = get_execution_action(client, action_id)

    if action_data["status"] not in ("PENDING", "FAILED"):
        raise ValueError("Action is not awaiting execution")

    if action_data["action"] != "REVOKE":
        raise ValueError("Unsupported CLOUD action")

    resource_id = action_data["target_resource_hash"].lower()

    existing = get_execution_action_record(action_id)

    if existing and existing["status"] == "EXECUTED":
        if existing["receipt"]:
            return existing["receipt"]
        raise ValueError("Execution is already recorded but has no receipt")

    timestamp = int(time.time())

    receipt = {
        "action_id": action_id,
        "domain": "CLOUD",
        "resource_id": resource_id,
        "action": "REVOKE",
        "status": "EXECUTED",
        "execution_mode": "SIMULATED",
        "timestamp": timestamp,
        "proof": {
            "description": "Simulated cloud token revocation"
        },
    }

    receipt_json = json.dumps(receipt, sort_keys=True)
    receipt["proof"]["sha256"] = hashlib.sha256(
        receipt_json.encode("utf-8")
    ).hexdigest()

    save_execution_action(
        action_id=action_id,
        domain="CLOUD",
        resource_id=resource_id,
        action="REVOKE",
        status="EXECUTED",
        receipt=receipt,
    )

    return receipt

def execute_oem_action(action_id: int) -> dict:
    client = BlockchainClient("OEM")
    action_data = get_execution_action(client, action_id)

    if action_data["status"] not in ("PENDING", "FAILED"):
        raise ValueError("Action is not awaiting execution")

    if action_data["action"] != "PATCH":
        raise ValueError("Unsupported OEM action")

    resource_id = "OEM-FIRMWARE-001"
    expected_hash = Web3.keccak(text=resource_id).hex()

    if action_data["target_resource_hash"].lower().removeprefix("0x") != expected_hash.lower().removeprefix("0x"):
        raise ValueError("Unknown OEM firmware resource hash")

    existing = get_execution_action_record(action_id)

    if existing and existing["status"] == "EXECUTED":
        if existing["receipt"]:
            return existing["receipt"]
        raise ValueError("Execution is already recorded but has no receipt")

    timestamp = int(time.time())

    receipt = {
        "action_id": action_id,
        "domain": "OEM",
        "resource_id": resource_id,
        "action": "PATCH",
        "status": "EXECUTED",
        "execution_mode": "SIMULATED",
        "timestamp": timestamp,
        "proof": {
            "description": "Simulated firmware patch preparation"
        },
    }

    receipt_json = json.dumps(receipt, sort_keys=True)
    receipt["proof"]["sha256"] = hashlib.sha256(
        receipt_json.encode("utf-8")
    ).hexdigest()

    save_execution_action(
        action_id=action_id,
        domain="OEM",
        resource_id=resource_id,
        action="PATCH",
        status="EXECUTED",
        receipt=receipt,
    )

    return receipt

def execute_user_action(action_id: int) -> dict:
    client = BlockchainClient("USER")
    action_data = get_execution_action(client, action_id)

    if action_data["status"] not in ("PENDING", "FAILED"):
        raise ValueError("Action is not awaiting execution")

    if action_data["action"] != "MONITOR":
        raise ValueError("Unsupported USER action")

    resource_id = "USER-ADMIN-001"
    expected_hash = Web3.keccak(text=resource_id).hex()

    if (
        action_data["target_resource_hash"].lower().removeprefix("0x")
        != expected_hash.lower().removeprefix("0x")
    ):
        raise ValueError("Unknown USER administrator resource hash")

    existing = get_execution_action_record(action_id)

    if existing and existing["status"] == "EXECUTED":
        if existing["receipt"]:
            return existing["receipt"]
        raise ValueError("Execution is already recorded but has no receipt")

    timestamp = int(time.time())

    receipt = {
        "action_id": action_id,
        "domain": "USER",
        "resource_id": resource_id,
        "action": "MONITOR",
        "status": "EXECUTED",
        "execution_mode": "SIMULATED",
        "timestamp": timestamp,
        "proof": {
            "description": "Simulated notification to the system administrator"
        },
    }

    receipt_json = json.dumps(receipt, sort_keys=True)
    receipt["proof"]["sha256"] = hashlib.sha256(
        receipt_json.encode("utf-8")
    ).hexdigest()

    save_execution_action(
        action_id=action_id,
        domain="USER",
        resource_id=resource_id,
        action="MONITOR",
        status="EXECUTED",
        receipt=receipt,
    )

    return receipt