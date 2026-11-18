
from gateway import transactions
from gateway.db import connect
from gateway.utils import incident_id_hash

MILESTONES = [
    ("IncidentRegistry", "IncidentRegistered", "registered"),
    ("CorrelationDecision", "CorrelationRecorded", "correlated"),
    ("ResponseProposal", "ProposalCreated", "proposed"),
    ("FederatedVoting", "VotingStarted", "voting_started"),
    ("ResponseDecision", "DecisionFinalized", "decided"),
    ("ResponseExecution", "ExecutionPlanCreated", "plan_created"),
    ("ExecutionVerification", "IncidentExecutionCompleted", "verified"),
    ("IncidentRegistry", "IncidentClosed", "closed"),
]


def transaction_stats(db_path=None):
    with connect(db_path or transactions.DB_PATH) as db:
        rows = db.execute("""
            SELECT function, COUNT(*) AS calls, AVG(gas_used) AS avg_gas, MAX(gas_used) AS max_gas,
                   AVG(confirmed_at - submitted_at) AS avg_latency_s, MAX(confirmed_at - submitted_at) AS max_latency_s
            FROM transactions WHERE status = 'SUCCESS' GROUP BY function ORDER BY function
        """).fetchall()
    return [dict(r) for r in rows]


def incident_timeline(listener, incident_id):
    id_hash = "0x" + incident_id_hash(incident_id).hex()
    events = listener.fetch_events(limit=100000)

    proposal_ids = {e["args"]["proposalId"] for e in events
                    if e["event"] == "ProposalCreated" and e["args"].get("incidentId") == id_hash}

    wanted = {(c, e): label for c, e, label in MILESTONES}
    timeline = []
    for e in events:
        label = wanted.get((e["contract"], e["event"]))
        if not label:
            continue
        args = e["args"]
        if args.get("incidentId") == id_hash or args.get("proposalId") in proposal_ids:
            timeline.append({"phase": label, "block": e["block_number"],
                             "timestamp": e["block_timestamp"], "event_id": e["id"]})

    timeline.sort(key=lambda t: t["event_id"])
    if timeline:
        t0 = timeline[0]["timestamp"]
        for t in timeline:
            t["seconds_since_start"] = t["timestamp"] - t0
    return timeline


def phase_latencies(timeline):
    return {f"{a['phase']}->{b['phase']}": b["timestamp"] - a["timestamp"]
            for a, b in zip(timeline, timeline[1:])}
