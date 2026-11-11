# Contributing to SlaErrorBudgetAuditor

Contributions that strengthen deterministic postmortem verification, quote anchoring, or test coverage are welcome.

## Development Workflow
1. Fork the repository and create a feature branch.
2. Install dependencies via `pip install -r requirements.txt`.
3. Run the verification suite locally:
   ```bash
   pytest -v
   ```
4. Ensure all new extraction rules preserve deterministic validator equivalence (`extract_consensus_facts`) and strict SHA-256 artifact pinning.
5. Open a Pull Request with a clear summary of changes.
