# Trivy Ecosystem Supply Chain Compromise Hunt

This folder covers the March 2026 Trivy ecosystem compromise, including the March 19 GitHub Actions and binary abuse, Docker follow-on exposure, OpenVSX extension context, and CanisterWorm downstream propagation boundaries.

## Deliverables
- [Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md](Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md) - primary hunt playbook, scoping logic, validation path, and response guidance.
- [trivy_teampcp_high_roi_kql_pack.md](trivy_teampcp_high_roi_kql_pack.md) - Microsoft Defender XDR and Sentinel KQL pack for scoping runner theft, follow-on persistence, and downstream package activity.
- [Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md](Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md) - normalized incident synthesis, timeline, and cluster boundaries.

## Notes
- This case intentionally keeps March 19 runner theft, Docker follow-on, OpenVSX, and CanisterWorm as related but separate clusters.
- The KQL pack is Defender and Sentinel-specific and still needs local schema, allowlist, and retention tuning.

## Suggested workflow
1. Read [Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md](Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md) to understand the timeline, boundaries, and safe-version anchors.
2. Use [trivy_teampcp_high_roi_kql_pack.md](trivy_teampcp_high_roi_kql_pack.md) to scope runners, persistence, suspicious egress, and downstream package activity in Defender or Sentinel.
3. Work validation and containment from [Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md](Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md).
