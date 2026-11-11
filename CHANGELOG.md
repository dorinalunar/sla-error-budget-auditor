# Changelog

All notable changes to `SlaErrorBudgetAuditor` are documented in this file.

## [1.0.0] - 2026-11-10
### Added
- Implemented `SlaErrorBudgetAuditor` GenVM Intelligent Contract (`SlaErrorBudgetAuditor.py`).
- Added commit-pinned GitHub raw URL and SHA-256 content verification (`verify_pinned_artifact`).
- Added deterministic verbatim quote anchoring (`anchor_evidence_excerpt`) with automatic line-level incident ID recovery.
- Implemented interval clamping and union merging (`compute_sla_accounting`) for parts-per-million (`uptime_ppm`) SLA accounting and error budget breach detection.
- Added GenVM non-deterministic LLM extraction with strict fact-level validator consensus (`gl.vm.run_nondet_unsafe`).
- Added unit and end-to-end test suite (`test_sla_error_budget_auditor.py`) and benchmark scenarios (`sample_dataset.json`).
