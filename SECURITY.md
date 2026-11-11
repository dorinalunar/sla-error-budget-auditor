# Security Policy & Threat Model

## Security Architecture
`SlaErrorBudgetAuditor` enforces a fail-closed security model across three verification layers:

1. **Cryptographic Artifact Pinning (`verify_pinned_artifact`)**:
   - Postmortem sources must use a 40-character hexadecimal git commit SHA under the bound `repo_slug` on `https://raw.githubusercontent.com/`.
   - Mutable branch refs (`main`, `master`) and path traversal sequences (`..`) are rejected prior to network execution.
   - Fetched HTTP payloads are bounded to 16 KB and verified against the charter's expected SHA-256 digest before parsing.

2. **Prompt-Injection Defense & Verbatim Quote Anchoring (`anchor_evidence_excerpt`)**:
   - Postmortem bodies are treated strictly as untrusted data.
   - Every non-empty LLM classification (`AFFECTED`, `UNAFFECTED`, `RESTORED`, `ONGOING`) must supply a verbatim contiguous substring from the verified document that contains both the exact `ref_id` (with word-boundary checks) and the literal `YYYY-MM-DDTHH:MM:SSZ` timestamp.
   - Hallucinated quotes or cross-incident timestamp borrowing cause an immediate deterministic revert.

3. **Fact-Equivalence Validator Consensus (`validator_consensus`)**:
   - Validators independently fetch the artifact, verify the SHA-256 digest, validate the leader's proposed excerpts against the raw document, and run their own extraction to verify 1:1 agreement on canonical facts (`ref_id`, `impact`, `resolution`, `onset_utc`, `resolved_utc`).
