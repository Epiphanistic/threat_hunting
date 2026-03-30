# LiteLLM and Trivy Markdown Integration Plan

## Current repository shape
- Hunt content lives in one topic folder per case.
- Folders are discoverable from the root `README.md`.
- Repo-facing artifacts are concise, reader-oriented Markdown deliverables, not working directories with helper scripts, virtual environments, or export tooling.

## Options considered
1. Import the source Markdown files as-is into the repository root.
Rejected: this breaks the existing foldered hunt layout and makes the new material harder to discover.

2. Copy the sibling `LiteLLM` and `TrivyHacks` directories wholesale.
Rejected: those directories contain PDFs, helper scripts, working notes, and local tooling that do not match this repo's portfolio shape.

3. Normalize the Markdown artifacts into repo-style hunt folders, rename files to match local conventions, preserve substantive content, and patch only the framing and broken references.
Chosen: this is the smallest contract-preserving change that keeps the source material intact while fitting the repository layout.

## Implementation decisions
- Create `LiteLLM_PyPI_Supply_Chain_Compromise/` with a hunt, OSINT report, KQL query pack, and folder `README.md`.
- Create `Trivy_Ecosystem_Supply_Chain_Compromise/` with a hunt, OSINT report, source-review notes, a repo-style query-priorities file, and folder `README.md`.
- Import Markdown only. Do not pull PDFs, virtual environments, helper scripts, or unrelated export artifacts into this repo.
- Keep LiteLLM queries in Kusto Query Language (KQL) rather than forcing a LogScale rewrite. Converting platforms here would change the artifact rather than normalize it.
- Remove generator-only instructions and broken references to absent JSON artifacts where they would leave dead links in the repo.
