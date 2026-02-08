# DLL Sideloading Campaign abusing ahost.exe Hunt

This hunt documents a multi-actor intrusion pattern where attackers abuse signed `ahost.exe` to load a malicious `libcares-2.dll`, then pivot into follow-on payload activity, including DCRat behavior through `AddInProcess32.exe`.

## Deliverables
- [DLL_Sideloading_Campaign_abusing_ahost_exe_hunt.md](DLL_Sideloading_Campaign_abusing_ahost_exe_hunt.md) - hunting strategy, triage logic, response path, and exit criteria.
- [DLL_Sideloading_Campaign_abusing_ahost_exe_Logscale_queries.md](DLL_Sideloading_Campaign_abusing_ahost_exe_Logscale_queries.md) - query pack aligned to behavior-chain detection.
- [DLL_Sideloading_Campaign_abusing_ahost_exe_OSINT_report.md](DLL_Sideloading_Campaign_abusing_ahost_exe_OSINT_report.md) - campaign profile, tradecraft interpretation, and source-backed context.
- [DLL_Sideloading_Campaign_abusing_ahost_exe_IOCs.json](DLL_Sideloading_Campaign_abusing_ahost_exe_IOCs.json) - structured indicators with confidence notes.
- [sources/](sources/) - source captures, dork trail, and source manifest.

## Core Analytical Position
- Signed binary trust is not enough; execution context and load path matter.
- Dynamic link library sideloading should be treated as a behavior pattern, not a single family signature.
- Domain and hash indicators are confirmation pivots, not primary detection strategy.

## Suggested Workflow
1. Read [DLL_Sideloading_Campaign_abusing_ahost_exe_OSINT_report.md](DLL_Sideloading_Campaign_abusing_ahost_exe_OSINT_report.md) to understand what is legitimate versus abused.
2. Run behavior-chain queries first from [DLL_Sideloading_Campaign_abusing_ahost_exe_Logscale_queries.md](DLL_Sideloading_Campaign_abusing_ahost_exe_Logscale_queries.md).
3. Validate suspicious hosts with [DLL_Sideloading_Campaign_abusing_ahost_exe_IOCs.json](DLL_Sideloading_Campaign_abusing_ahost_exe_IOCs.json).
4. Execute triage and containment steps in [DLL_Sideloading_Campaign_abusing_ahost_exe_hunt.md](DLL_Sideloading_Campaign_abusing_ahost_exe_hunt.md).
