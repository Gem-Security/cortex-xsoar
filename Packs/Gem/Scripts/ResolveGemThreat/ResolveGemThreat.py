from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    incident.get("closeReason", "")
    close_notes = incident.get("closeNotes", "")
    incident_id = incident.get("id", "")
    threat_id = incident.get("CustomFields").get("threatid")
    verdict = incident.get("CustomFields").get("verdict")
    verdict = verdict if verdict != "" else "inconclusive"
    verdict = verdict.replace(" ", "_").lower()
    status = "resolved"

    demisto.executeCommand("gem-update-threat-status", {
        "verdict": verdict,
        "reason": f"Closed from XSOAR, incident id: {incident_id}\n"
        f"\nClose Notes:\n{close_notes}",
        "threat_id": threat_id,
        "status": status})
    demisto.log(f"Resolved Gem Threat {threat_id} with status {status}, verdict {verdict} and close notes {close_notes}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
