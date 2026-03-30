# LiteLLM PyPI Supply Chain Compromise Hunt

This folder covers the March 2026 compromise of malicious `litellm` PyPI releases `1.82.7` and `1.82.8`, with emphasis on Python startup-hook execution, credential theft, exfiltration staging, and Kubernetes follow-on risk.

## Deliverables
- [LiteLLM_PyPI_Supply_Chain_Compromise_hunt.md](LiteLLM_PyPI_Supply_Chain_Compromise_hunt.md) - primary hunt playbook, triage path, containment guidance, and exit criteria.
- [LiteLLM_PyPI_Supply_Chain_Compromise_KQL_queries.md](LiteLLM_PyPI_Supply_Chain_Compromise_KQL_queries.md) - Microsoft Defender XDR and Microsoft Sentinel KQL query pack aligned to the hunt.
- [LiteLLM_PyPI_Supply_Chain_Compromise_OSINT_report.md](LiteLLM_PyPI_Supply_Chain_Compromise_OSINT_report.md) - source-backed incident profile, timeline, blast-radius analysis, and mitigation guidance.

## Notes
- This case keeps the original KQL form because the source artifact was already platform-specific and converting it to LogScale would change the deliverable rather than normalize it.
- Treat any confirmed `litellm==1.82.7` or `1.82.8` exposure as a credential-compromise investigation, not as a routine dependency issue.

## Suggested workflow
1. Read [LiteLLM_PyPI_Supply_Chain_Compromise_OSINT_report.md](LiteLLM_PyPI_Supply_Chain_Compromise_OSINT_report.md) for the timeline, blast radius, and incident mechanics.
2. Use [LiteLLM_PyPI_Supply_Chain_Compromise_KQL_queries.md](LiteLLM_PyPI_Supply_Chain_Compromise_KQL_queries.md) to scope affected hosts, runners, and Kubernetes activity.
3. Execute triage and containment steps from [LiteLLM_PyPI_Supply_Chain_Compromise_hunt.md](LiteLLM_PyPI_Supply_Chain_Compromise_hunt.md).
