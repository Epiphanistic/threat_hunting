# Trivy Ecosystem Supply Chain Compromise Hunt

This folder covers the March 2026 Trivy ecosystem compromise, including the March 19 GitHub Actions and binary abuse, Docker follow-on exposure, OpenVSX extension context, and CanisterWorm downstream propagation boundaries.

## Deliverables
- [Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md](Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md) - primary hunt playbook, scoping logic, validation path, and response guidance.
- [Trivy_Ecosystem_Supply_Chain_Compromise_Logscale_queries.md](Trivy_Ecosystem_Supply_Chain_Compromise_Logscale_queries.md) - repo-style query priorities and scoping pivots for building or tuning platform-specific detections.
- [Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md](Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md) - normalized incident synthesis, timeline, and cluster boundaries.
- [Trivy_Ecosystem_Supply_Chain_Compromise_source_review_notes.md](Trivy_Ecosystem_Supply_Chain_Compromise_source_review_notes.md) - supporting PDF-only review notes that preserve cluster separation and source disagreements.

## Notes
- This case intentionally keeps March 19 runner theft, Docker follow-on, OpenVSX, and CanisterWorm as related but separate clusters.
- The query file is a repo-shaped scoping artifact, not a fully built platform-specific query pack.

## Suggested workflow
1. Read [Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md](Trivy_Ecosystem_Supply_Chain_Compromise_OSINT_report.md) to understand the timeline, boundaries, and safe-version anchors.
2. Use [Trivy_Ecosystem_Supply_Chain_Compromise_Logscale_queries.md](Trivy_Ecosystem_Supply_Chain_Compromise_Logscale_queries.md) to scope workflows, runners, Docker pulls, and downstream follow-on activity.
3. Work validation and containment from [Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md](Trivy_Ecosystem_Supply_Chain_Compromise_hunt.md), then use [Trivy_Ecosystem_Supply_Chain_Compromise_source_review_notes.md](Trivy_Ecosystem_Supply_Chain_Compromise_source_review_notes.md) when you need source-separation detail.
