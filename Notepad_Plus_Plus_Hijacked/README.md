# Notepad++ WinGUp Hijack Hunt

This folder covers the reported WinGUp updater hijack activity affecting Notepad++ versions prior to 8.8.9. It includes a hypothesis-driven hunt playbook, LogScale query pack, OSINT consolidation, and a structured IOC JSON.

## Contents
- [Notepad_Plus_Plus_Hijacked_hunt.md](Notepad_Plus_Plus_Hijacked_hunt.md) – primary hunt playbook (scope, hypothesis, MITRE mapping, triage, exit criteria).
- [Notepad_Plus_Plus_Hijacked_Logscale_queries.md](Notepad_Plus_Plus_Hijacked_Logscale_queries.md) – LogScale query pack aligned to the playbook.
- [Notepad_Plus_Plus_Hijacked_IOCs.json](Notepad_Plus_Plus_Hijacked_IOCs.json) – structured IOC list with attribution, confidence, and notes.
- [Notepad_Hijacked_OSINT_Report.md](Notepad_Hijacked_OSINT_Report.md) – OSINT summary, timeline, and source list.

## Notes
- Indicators are incident-reported and may be context-specific; validate with process lineage, signer metadata, and time alignment.
- Baseline update infrastructure (Notepad++ and GitHub release domains) is included in the IOC JSON for comparison.
- No public malicious hashes were found in reviewed sources at time of writing.

## Suggested workflow
1) Review [Notepad_Hijacked_OSINT_Report.md](Notepad_Hijacked_OSINT_Report.md) for context and timeline.
2) Run the exposure and update-chain queries in [Notepad_Plus_Plus_Hijacked_Logscale_queries.md](Notepad_Plus_Plus_Hijacked_Logscale_queries.md).
3) Use [Notepad_Plus_Plus_Hijacked_IOCs.json](Notepad_Plus_Plus_Hijacked_IOCs.json) to validate suspicious artifacts and network indicators.
4) Follow triage and exit criteria in [Notepad_Plus_Plus_Hijacked_hunt.md](Notepad_Plus_Plus_Hijacked_hunt.md).
