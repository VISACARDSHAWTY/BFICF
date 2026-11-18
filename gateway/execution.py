from web3 import Web3

from gateway.hashing import commitment_bytes
from gateway.transactions import TransactionManager
from gateway.utils import to_hex


EXECUTION_ACTIONS = {
    "QUARANTINE": 0,
    "PATCH": 1,
    "REVOKE": 2,
    "BLOCK_TRAFFIC": 3,
    "MONITOR": 4,
}

DECISION_ACTIONS = {0: "QUARANTINE", 1: "PATCH", 2: "REVOKE", 3: "MONITOR"}

ACTION_NAMES = {0: "QUARANTINE", 1: "PATCH", 2: "REVOKE", 3: "BLOCK_TRAFFIC", 4: "MONITOR", 5: "NO_ACTION"}
STATUS_NAMES = {0: "PENDING", 1: "SUBMITTED", 2: "VERIFIED", 3: "FAILED"}


def _hash_value(value):
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value)
        return value if len(value) == 32 else bytes(Web3.keccak(value))

    if isinstance(value, str) and value.startswith("0x") and len(value) == 66:
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            pass

    return commitment_bytes(value)


def _resolve_domain(client, domain):
    address = client.resolve_domain_address(domain)
    if not client.get_contract("DomainRegistry").functions.isActiveDomain(address).call():
        raise ValueError(f"Domain is not active: {address}")
    return address


def _action_name(action):
    if isinstance(action, str):
        action = action.upper()
        if action not in EXECUTION_ACTIONS:
            raise ValueError(f"Invalid execution action: {action}")
        return action

    if action not in ACTION_NAMES:
        raise ValueError(f"Invalid execution action: {action}")
    return ACTION_NAMES[action]


def create_execution_plan(client, proposal_id, actions):
    if not actions:
        raise ValueError("At least one execution action is required")
    if len(actions) > 16:
        raise ValueError("Maximum of 16 execution actions allowed")

    proposal_contract = client.get_contract("ResponseProposal")
    decision_contract = client.get_contract("ResponseDecision")
    execution_contract = client.get_contract("ResponseExecution")

    proposal = proposal_contract.functions.proposals(proposal_id).call()
    if proposal[5] == 0:
        raise ValueError("Proposal does not exist")
    if proposal[7] != 1:
        raise ValueError("Proposal is not approved")

    decision = decision_contract.functions.decisions(proposal_id).call()
    if not decision[5]:
        raise ValueError("Decision has not been finalized")
    if decision[0] not in DECISION_ACTIONS:
        raise ValueError("Decision does not authorize execution")

    decided_action = DECISION_ACTIONS[decision[0]]
    if not any(_action_name(item["action"]) == decided_action for item in actions):
        raise ValueError(f"Execution plan must include the decided action: {decided_action}")

    inputs = []
    for item in actions:
        responsible_domain = _resolve_domain(client, item["responsible_domain"])
        action_name = _action_name(item["action"])

        if action_name != decided_action:
            if not proposal_contract.functions.hasAction(proposal_id, EXECUTION_ACTIONS[action_name]).call():
                raise ValueError(f"{action_name} is not included in the approved proposal")

        if "details" not in item:
            raise ValueError("Every action requires off-chain details")

        inputs.append((responsible_domain, EXECUTION_ACTIONS[action_name], _hash_value(item["details"])))

    eligible = proposal_contract.functions.isEligibleVoter(proposal_id, client.address).call()
    if client.address != proposal[1] and not eligible:
        raise ValueError("Current account is not authorised to create this plan")

    result = TransactionManager(client).send(
        execution_contract.functions.createExecutionPlan(proposal_id, inputs),
        idempotency_key=f"execution-plan:{proposal_id}"
    )

    action_ids = execution_contract.functions.getProposalActionIds(proposal_id).call()

    return {
        "proposal_id": proposal_id,
        "incident_id": to_hex(proposal[0]),
        "decided_action": decided_action,
        "action_ids": action_ids,
        "status": "EXECUTION_PLAN_CREATED",
        **result
    }


def get_execution_action(client, action_id):
    action = client.get_contract("ResponseExecution").functions.getAction(action_id).call()

    return {
        "action_id": action_id,
        "proposal_id": action[0],
        "incident_id": to_hex(action[1]),
        "responsible_domain": action[2],
        "action": ACTION_NAMES[action[3]],
        "target_resource_hash": to_hex(action[4]),
        "details_hash": to_hex(action[5]),
        "receipt_hash": to_hex(action[6]),
        "reported_at": action[7],
        "status": STATUS_NAMES[action[8]],
    }


def report_execution(client, action_id, receipt):
    contract = client.get_contract("ResponseExecution")
    action = contract.functions.getAction(action_id).call()

    if action[2] != client.address:
        raise ValueError("Current account is not the responsible domain")
    if action[8] not in (0, 3):
        raise ValueError("Action is not awaiting an execution receipt")

    receipt_hash = _hash_value(receipt)
    if receipt_hash == bytes(action[6]):
        raise ValueError("Receipt must differ from the previously submitted receipt")

    result = TransactionManager(client).send(
        contract.functions.reportExecution(action_id, receipt_hash),
        idempotency_key=f"execution-receipt:{action_id}:{receipt_hash.hex()}"
    )

    return {"action_id": action_id, "receipt_hash": to_hex(receipt_hash),
            "status": "RECEIPT_SUBMITTED", **result}


def attest_action(client, action_id, valid=True):
    verification = client.get_contract("ExecutionVerification")
    execution = client.get_contract("ResponseExecution")

    action = execution.functions.getAction(action_id).call()

    if action[8] != 1:
        raise ValueError("Action does not have a submitted receipt")
    if action[2] == client.address:
        raise ValueError("Responsible domain cannot attest to its own receipt")
    if not client.get_contract("DomainRegistry").functions.isActiveDomain(client.address).call():
        raise ValueError("Current account is not an active domain")

    receipt_hash = bytes(action[6]).hex()

    result = TransactionManager(client).send(
        verification.functions.attestAction(action_id, bool(valid)),
        idempotency_key=f"execution-attestation:{action_id}:{receipt_hash}:{client.address.lower()}"
    )

    updated_action = get_execution_action(client, action_id)

    return {
        "action_id": action_id,
        "attestation": "APPROVE" if valid else "REJECT",
        "action_status": updated_action["status"],
        **result
    }


def get_execution_progress(client, proposal_id):
    execution = client.get_contract("ResponseExecution")
    verification = client.get_contract("ExecutionVerification")

    plan = execution.functions.executionPlans(proposal_id).call()
    if not plan[4]:
        return {"proposal_id": proposal_id, "created": False}

    progress = execution.functions.getPlanProgress(proposal_id).call()
    action_ids = execution.functions.getProposalActionIds(proposal_id).call()

    return {
        "proposal_id": proposal_id,
        "created": True,
        "escalated": plan[5],
        "deadline": plan[3],
        "total_actions": progress[1],
        "verified_actions": progress[2],
        "complete": progress[3],
        "required_attestations": verification.functions.requiredAttestations().call(),
        "actions": [get_execution_action(client, a) for a in action_ids],
    }


def escalate_stalled_execution(client, proposal_id):
    execution = client.get_contract("ResponseExecution")

    result = TransactionManager(client).send(
        execution.functions.escalateStalled(proposal_id),
        idempotency_key=f"execution-escalation:{proposal_id}"
    )
    return {"proposal_id": proposal_id, "status": "EXECUTION_ESCALATED", **result}
