# Lotus Blossom / Billbug Notepad++ Update Hijack Hunt

This folder covers the reported WinGUp updater hijack activity affecting Notepad++ versions prior to 8.8.9 and the associated Chrysalis backdoor analysis. It includes a hypothesis-driven hunt playbook, LogScale query pack, OSINT consolidation, and a structured IOC JSON.

## Contents
- [LotusBlossom_Billbug_Notepad++_hijack_hunt.md](LotusBlossom_Billbug_Notepad++_hijack_hunt.md) – primary hunt playbook (scope, hypothesis, MITRE mapping, triage, exit criteria).
- [LotusBlossom_Billbug_Notepad++_hijack_Logscale_queries.md](LotusBlossom_Billbug_Notepad++_hijack_Logscale_queries.md) – LogScale query pack aligned to the playbook.
- [LotusBlossom_Billbug_Notepad++_hijack_IOCs.json](LotusBlossom_Billbug_Notepad++_hijack_IOCs.json) – structured IOC list with attribution, confidence, and notes.
- [LotusBlossom_Billbug_Notepad++_hijack_OSINT_Report.md](LotusBlossom_Billbug_Notepad++_hijack_OSINT_Report.md) – OSINT summary, timeline, and source list.
- [LotusBlossom_attacker_infrastructure_analysis_based_on_censys_report.md](LotusBlossom_attacker_infrastructure_analysis_based_on_censys_report.md) – Censys‑driven infrastructure analysis with behavioral patterns, challenges, OSINT mapping, and a table view.

## Notes
- Indicators are incident-reported and may be context-specific; validate with process lineage, signer metadata, and time alignment.
- Baseline update infrastructure (Notepad++ and GitHub release domains) is included in the IOC JSON for comparison.
- Rapid7 published specific hashes; treat all third-party IoCs as incident-specific until validated.

## Suggested workflow
1) Review [LotusBlossom_Billbug_Notepad++_hijack_OSINT_Report.md](LotusBlossom_Billbug_Notepad++_hijack_OSINT_Report.md) for context and timeline.
2) Run the exposure and update-chain queries in [LotusBlossom_Billbug_Notepad++_hijack_Logscale_queries.md](LotusBlossom_Billbug_Notepad++_hijack_Logscale_queries.md).
3) Use [LotusBlossom_Billbug_Notepad++_hijack_IOCs.json](LotusBlossom_Billbug_Notepad++_hijack_IOCs.json) to validate suspicious artifacts and network indicators.
4) Use [LotusBlossom_attacker_infrastructure_analysis_based_on_censys_report.md](LotusBlossom_attacker_infrastructure_analysis_based_on_censys_report.md) to understand infrastructure behavior patterns and supporting OSINT.
5) Follow triage and exit criteria in [LotusBlossom_Billbug_Notepad++_hijack_hunt.md](LotusBlossom_Billbug_Notepad++_hijack_hunt.md).


