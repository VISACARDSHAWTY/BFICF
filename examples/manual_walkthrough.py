
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway.client import BlockchainClient
from gateway import (incidents, evidence, correlations, response_proposals as rp, voting, execution,
                     decisions, devices, recovery)
from gateway.event_listener import BlockchainEventListener
from gateway import metrics

parser = argparse.ArgumentParser()
parser.add_argument("--time-travel", action="store_true", help="use evm_increaseTime (hardhat only)")
args = parser.parse_args()


def step(title):
    print(f"\n=== {title}")


def wait_chain_time(client, target):
    """Wait until CHAIN time reaches `target`."""
    while client.chain_time() < target:
        remaining = target - client.chain_time()
        if args.time_travel:
            client.w3.provider.make_request("evm_increaseTime", [remaining + 1])
            client.w3.provider.make_request("evm_mine", [])
        else:
            print(f"   waiting {remaining}s of chain time ...")
            time.sleep(min(remaining + 1, 5))


c = {n: BlockchainClient(n) for n in ("OEM", "CLOUD", "EDGE", "USER", "SECAUTH", "CORRELATOR", "RECOVERY_VERIFIER")}
edge, cloud, user, oem = c["EDGE"], c["CLOUD"], c["USER"], c["OEM"]
uid = int(time.time())
incident_id, device = f"INC-demo-{uid}", f"device-demo-{uid}"

listener = BlockchainEventListener(edge)          # stores every event for the timeline at the end

step("1. register incident (EDGE)")
print(incidents.register_incident(edge, incident_id, {"device": device, "signal": "beacon"}, "CYBER", 7, edge.chain_time()))

step("2. commit evidence (EDGE)")
print(evidence.commit_evidence(edge, incident_id, {"pcap_sha256": "ab" * 32}))

step("3. correlation: CORRELATOR submits, affected domains attest")
sub = correlations.submit_correlation(c["CORRELATOR"], incident_id, {"cluster": [device]}, "HIGH",
                                      ["EDGE", "CLOUD", "USER"], "algo-v1")
correlations.attest_correlation(edge, incident_id, sub["result_hash"])
correlations.attest_correlation(cloud, incident_id, sub["result_hash"])
print(correlations.get_correlation_status(edge, incident_id)["finalized"], incidents.get_incident_state(edge, incident_id))

step("4. proposal (EDGE)")
proposal = rp.create_response_proposal(edge, incident_id, "EDGE", device, ["QUARANTINE", "BLOCK_TRAFFIC"],
                                       {"reason": "beaconing"}, 3600)
pid = proposal["proposal_id"]
print("proposal id", pid, rp.get_response_proposal(edge, pid)["status"])

step("5. commit-reveal vote (EDGE, CLOUD, USER all vote QUARANTINE)")
voting.start_voting(edge, pid)
for client in (edge, cloud, user):
    print(client.domain, voting.commit_vote(client, pid, "QUARANTINE")["status"])
session = voting.get_voting_session(edge, pid)
wait_chain_time(edge, session["commit_end"])
for client in (edge, cloud, user):
    print(client.domain, voting.reveal_vote(client, pid)["status"])
wait_chain_time(edge, session["reveal_end"])

step("6. finalize voting (anyone, here OEM) and read the decision")
print(voting.finalize_voting(oem, pid)["status"], decisions.get_decision(edge, pid))

step("7. execution plan, receipts, peer attestation")
plan = execution.create_execution_plan(edge, pid, [
    {"responsible_domain": "EDGE", "action": "QUARANTINE", "details": {"cmd": "isolate"}},
    {"responsible_domain": "CLOUD", "action": "BLOCK_TRAFFIC", "details": {"cmd": "drop"}}])
a1, a2 = plan["action_ids"]
execution.report_execution(edge, a1, {"done": True})
execution.report_execution(cloud, a2, {"done": True})
execution.attest_action(cloud, a1, True)
execution.attest_action(user, a2, True)
print(execution.get_execution_progress(edge, pid)["complete"], incidents.get_incident_state(edge, incident_id))

step("8. close incident (USER) with a closure record")
print(incidents.close_incident(user, incident_id, {"summary": "device isolated"})["status"])

step("9. device state enforced from the decision, then recovery")
devices.register_device(edge, device, {"model": "demo"})
devices.apply_decision(cloud, device, pid)
print(devices.get_device(edge, device)["state"])
req = recovery.submit_recovery_request(edge, device, *["0x" + f"{i:02x}" * 32 for i in range(1, 5)])
recovery.validate_recovery(cloud, req["request_id"], True)
recovery.finalize_recovery(c["RECOVERY_VERIFIER"], req["request_id"], True, "0x" + "ab" * 32)
print(devices.get_device(edge, device)["state"])

step("10. measurements")
listener.poll_once()
timeline = metrics.incident_timeline(listener, incident_id)
print("phase latencies (s):", metrics.phase_latencies(timeline))
for row in metrics.transaction_stats():
    print(f"   {row['function']:<24} calls={row['calls']:<3} avg_gas={int(row['avg_gas'] or 0):<8} avg_latency_s={row['avg_latency_s']}")
print("\nDone.")
