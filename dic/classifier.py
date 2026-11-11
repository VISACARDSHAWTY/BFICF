
def classify_incident(incident: dict) -> str:
    incident_type = incident["incident_type"].upper()
    severity = incident["severity"]

    if incident_type == "CYBER":
        return "CRITICAL_CYBER" if severity >= 8 else "CYBER"

    if incident_type == "HARDWARE":
        return "CRITICAL_HARDWARE" if severity >= 8 else "HARDWARE"

    if incident_type == "SOFTWARE":
        return "CRITICAL_SOFTWARE" if severity >= 8 else "SOFTWARE"

    raise ValueError("Unsupported incident type")
