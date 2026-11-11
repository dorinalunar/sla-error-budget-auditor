# SlaErrorBudgetAuditor

**Deterministic SLA Error-Budget & Postmortem Availability Auditor on GenLayer (GenVM)**

`SlaErrorBudgetAuditor` is a GenLayer Intelligent Contract that bridges unstructured infrastructure incident postmortems with deterministic on-chain SLA accounting. It fetches commit-pinned incident reports from GitHub, verifies SHA-256 payload integrity, extracts structured outage intervals via GenVM LLM consensus with verbatim quote anchoring, and computes merged downtime seconds, parts-per-million availability (`uptime_ppm`), and error-budget breach status.

---

## Key Capabilities

- **Commit-Pinned Artifact Integrity**: Enforces immutable 40-character commit SHA URLs on `raw.githubusercontent.com` paired with on-chain SHA-256 digest verification before any LLM processing.
- **Verbatim Quote & Timestamp Anchoring**: Requires every extracted outage classification (`AFFECTED`, `UNAFFECTED`, `UNKNOWN`) and lifecycle state (`RESTORED`, `ONGOING`, `UNKNOWN`) to be backed by an exact contiguous quote from the source postmortem containing both the incident `ref_id` and literal `YYYY-MM-DDTHH:MM:SSZ` timestamp.
- **Deterministic Interval Union Math**: Clamps outage windows to the monitored epoch, merges overlapping or adjacent multi-incident outages so concurrent incidents are never double-counted, and computes exact `downtime_seconds` and `uptime_ppm`.
- **Two-Stage Validator Consensus**: Uses `gl.vm.run_nondet_unsafe` where validators independently verify the leader's source quotes against the raw document and compare canonical incident facts (`extract_consensus_facts`).

---

## Repository Structure

```text
├── .github/workflows/ci.yml          # Automated pytest CI pipeline
├── .env.example                      # Environment & RPC template
├── .gitignore                        # Standard Python & build ignores
├── CHANGELOG.md                      # Version history
├── CONTRIBUTING.md                   # Developer workflow guidelines
├── LICENSE                           # MIT License
├── README.md                         # Project documentation
├── SECURITY.md                       # Threat model & security guarantees
├── SlaErrorBudgetAuditor.py          # GenVM Intelligent Contract
├── requirements.txt                  # Python test dependencies
├── sample_dataset.json               # End-to-end SLA audit test vectors
└── test_sla_error_budget_auditor.py  # Pytest unit & consensus test suite
```

---

## Contract Interface

### Constructor
- `__init__(repo_slug: str)` — Binds the contract to an authorized GitHub `owner/repository` slug and assigns the deployer as `governor`.

### Write Methods
- `register_charter(epoch_id: str, charter_json: str) -> None` — Registers an SLA monitoring charter specifying `service_tier`, `deployment_zone`, `window_start`, `window_end`, `error_budget_sec`, `outage_refs`, and the pinned `artifact` (`url`, `sha256`).
- `audit_epoch(epoch_id: str) -> None` — Fetches the pinned postmortem report, validates its SHA-256 hash, executes non-deterministic LLM extraction with validator consensus, and stores the finalized SLA accounting record.

### View Methods
- `protocol_version() -> str` — Returns `"SlaErrorBudgetAuditor/v1.0"`.
- `get_charter(epoch_id: str) -> str` — Returns the canonical JSON charter for `epoch_id`.
- `get_audit(epoch_id: str) -> str` — Returns the finalized audit report JSON (`accounting_status`, `downtime_seconds`, `uptime_ppm`, `budget_breached`, `merged_intervals`, `records`).
- `has_complete_accounting(epoch_id: str) -> bool` — Returns `True` if the epoch has been audited and all declared outage references resolved with `COMPLETE` status.

---

## Running Tests Locally

```bash
pip install -r requirements.txt
pytest -v
```
