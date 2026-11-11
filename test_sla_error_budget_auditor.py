import contextlib
import hashlib
import json
from pathlib import Path
import re
import sys
import types

try:
    import pytest
except ImportError:
    class _FallbackPytest:
        @staticmethod
        @contextlib.contextmanager
        def raises(exc_type, match=None):
            try:
                yield
            except exc_type as exc:
                if match and not re.search(match, str(exc)):
                    raise AssertionError(f"Pattern {match!r} not found in {str(exc)!r}")
                return
            raise AssertionError(f"Did not raise {exc_type}")

    pytest = _FallbackPytest()


def _install_genlayer_mock():
    if "genlayer" in sys.modules:
        return

    mock_gl = types.ModuleType("genlayer")

    class _UserError(Exception):
        pass

    class _Return:
        def __init__(self, calldata):
            self.calldata = calldata

    class _VM:
        UserError = _UserError
        Return = _Return

        @staticmethod
        def run_nondet_unsafe(leader_fn, validator_fn):
            result = leader_fn()
            wrapped = _Return(result)
            if not validator_fn(wrapped):
                raise _UserError("Validator rejected leader assessment")
            return result

    class _WebResponse:
        def __init__(self, status: int, body: bytes):
            self.status = status
            self.body = body

    class _Web:
        _mock_get = None

        @classmethod
        def get(cls, url: str):
            if callable(cls._mock_get):
                return cls._mock_get(url)
            if cls._mock_get is not None:
                return cls._mock_get
            raise _UserError("No mock web response configured")

    class _Nondet:
        web = _Web
        _mock_response = None

        @classmethod
        def exec_prompt(cls, prompt_text: str, response_format: str = "json"):
            if callable(cls._mock_response):
                return cls._mock_response(prompt_text)
            if cls._mock_response is not None:
                return cls._mock_response
            raise _UserError("No mock LLM response configured")

    class _PublicProxy:
        def write(self, fn):
            return fn

        def view(self, fn):
            return fn

    class Address(str):
        pass

    class _Message:
        sender_address = Address("0x38409cCa5f5ca70F3fe189638a87862318b478dd")
        contract_address = Address("0x45d5b9fCEe51A8E58327E6C9eCa060bc7777559c")
        chain_id = 61999

    class _Contract:
        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)
            orig_init = cls.__init__

            def _wrapped_init(self, *args, **kw):
                for attr in getattr(cls, "__annotations__", {}):
                    setattr(self, attr, {})
                orig_init(self, *args, **kw)

            cls.__init__ = _wrapped_init

    class _TreeMapMeta(type):
        def __getitem__(cls, item):
            return dict

    class TreeMap(dict, metaclass=_TreeMapMeta):
        pass

    mock_gl.vm = _VM
    mock_gl.nondet = _Nondet
    mock_gl.public = _PublicProxy()
    mock_gl.message = _Message
    mock_gl.Contract = _Contract
    mock_gl.Address = Address
    mock_gl.TreeMap = TreeMap
    mock_gl.u256 = int
    mock_gl.gl = mock_gl
    mock_gl._WebResponse = _WebResponse
    mock_gl.__all__ = ["gl", "Address", "TreeMap", "u256"]

    sys.modules["genlayer"] = mock_gl


_install_genlayer_mock()

import genlayer as gl_mod  # noqa: E402
from SlaErrorBudgetAuditor import (  # noqa: E402
    PROTOCOL_TAG,
    SlaErrorBudgetAuditor,
    anchor_evidence_excerpt,
    compute_sla_accounting,
    parse_utc_epoch,
    verify_pinned_artifact,
)

GOVERNOR = gl_mod.Address("0x38409cCa5f5ca70F3fe189638a87862318b478dd")
STRANGER = gl_mod.Address("0x9999999999999999999999999999999999999999")
REPO_SLUG = "dorinalunar/sla-error-budget-auditor"


def test_utc_parser_and_pinned_artifact_validation():
    t0 = parse_utc_epoch("2026-10-05T00:00:00Z")
    t1 = parse_utc_epoch("2026-10-05T01:00:00Z")
    assert t1 - t0 == 3600

    with pytest.raises(gl_mod.gl.vm.UserError, match="ISO-8601 UTC"):
        parse_utc_epoch("2026-10-05 00:00:00")

    valid_artifact = {
        "url": f"https://raw.githubusercontent.com/{REPO_SLUG}/a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4/reports/q4.md",
        "sha256": "a" * 64,
    }
    verify_pinned_artifact(valid_artifact, REPO_SLUG)

    with pytest.raises(gl_mod.gl.vm.UserError, match="commit-pinned"):
        verify_pinned_artifact(
            {
                "url": f"https://raw.githubusercontent.com/{REPO_SLUG}/main/reports/q4.md",
                "sha256": "a" * 64,
            },
            REPO_SLUG,
        )


def test_excerpt_line_expansion_and_id_boundary_check():
    doc = "INC-101: Outage began at 2026-10-05T14:00:00Z and ended at 2026-10-05T14:30:00Z.\n"
    anchored = anchor_evidence_excerpt(doc, "ended at 2026-10-05T14:30:00Z.", "INC-101")
    assert "INC-101:" in anchored

    with pytest.raises(gl_mod.gl.vm.UserError, match="exact outage ref_id"):
        anchor_evidence_excerpt(doc, "Outage began at 2026-10-05T14:00:00Z", "INC-10")


def test_end_to_end_sample_dataset_audit():
    dataset_path = Path(__file__).parent / "sample_dataset.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    assert dataset["protocol"] == PROTOCOL_TAG

    gl_mod.gl.message.sender_address = GOVERNOR
    contract = SlaErrorBudgetAuditor(REPO_SLUG)
    assert contract.protocol_version() == PROTOCOL_TAG

    scenario = dataset["scenarios"][0]
    epoch_id = scenario["epoch_id"]
    charter_str = json.dumps(scenario["charter"])

    gl_mod.gl.message.sender_address = STRANGER
    with pytest.raises(gl_mod.gl.vm.UserError, match="Only governor"):
        contract.register_charter(epoch_id, charter_str)

    gl_mod.gl.message.sender_address = GOVERNOR
    contract.register_charter(epoch_id, charter_str)

    body_bytes = scenario["document_body"].encode("utf-8")
    gl_mod.gl.nondet.web._mock_get = lambda url: gl_mod._WebResponse(200, body_bytes)
    gl_mod.gl.nondet._mock_response = lambda prompt: {"records": [dict(r) for r in scenario["mock_llm_records"]]}

    contract.audit_epoch(epoch_id)
    assert contract.has_complete_accounting(epoch_id) is True

    audit_report = json.loads(contract.get_audit(epoch_id))
    expected = scenario["expected_accounting"]
    assert audit_report["accounting_status"] == expected["accounting_status"]
    assert audit_report["downtime_seconds"] == expected["downtime_seconds"]
    assert audit_report["uptime_ppm"] == expected["uptime_ppm"]
    assert audit_report["budget_breached"] == expected["budget_breached"]
    assert audit_report["merged_intervals"] == expected["merged_intervals"]


def test_ongoing_outage_and_incomplete_accounting():
    charter = {
        "service_tier": "Sequencer RPC",
        "deployment_zone": "eu-central-1",
        "window_start": "2026-10-05T00:00:00Z",
        "window_end": "2026-10-05T02:00:00Z",
        "error_budget_sec": 900,
        "outage_refs": ["INC-201"],
        "artifact": {
            "url": f"https://raw.githubusercontent.com/{REPO_SLUG}/" + "b" * 40 + "/rep.md",
            "sha256": "c" * 64,
        },
    }
    ongoing_records = [
        {
            "ref_id": "INC-201",
            "impact": "AFFECTED",
            "impact_excerpt": "INC-201: Sequencer RPC in eu-central-1 down",
            "resolution": "ONGOING",
            "onset_utc": "2026-10-05T01:30:00Z",
            "resolved_utc": "",
            "onset_excerpt": "INC-201: down at 2026-10-05T01:30:00Z",
            "resolved_excerpt": "INC-201: outage remained active past 2026-10-05T02:00:00Z window end",
        }
    ]
    res = compute_sla_accounting(charter, ongoing_records)
    assert res["accounting_status"] == "COMPLETE"
    assert res["downtime_seconds"] == 1800
    assert res["budget_breached"] is True

    unknown_records = [
        {
            "ref_id": "INC-201",
            "impact": "UNKNOWN",
            "impact_excerpt": "",
            "resolution": "UNKNOWN",
            "onset_utc": "",
            "resolved_utc": "",
            "onset_excerpt": "",
            "resolved_excerpt": "",
        }
    ]
    res_inc = compute_sla_accounting(charter, unknown_records)
    assert res_inc["accounting_status"] == "INCOMPLETE"
    assert res_inc["downtime_seconds"] == 0


def test_sha256_mismatch_halts_audit():
    gl_mod.gl.message.sender_address = GOVERNOR
    contract = SlaErrorBudgetAuditor(REPO_SLUG)
    charter = {
        "service_tier": "Sequencer RPC",
        "deployment_zone": "eu-central-1",
        "window_start": "2026-10-05T00:00:00Z",
        "window_end": "2026-10-05T02:00:00Z",
        "error_budget_sec": 900,
        "outage_refs": ["INC-301"],
        "artifact": {
            "url": f"https://raw.githubusercontent.com/{REPO_SLUG}/" + "b" * 40 + "/rep.md",
            "sha256": "f" * 64,
        },
    }
    contract.register_charter("epoch-bad-hash", json.dumps(charter))
    gl_mod.gl.nondet.web._mock_get = lambda url: gl_mod._WebResponse(200, b"tampered body content")

    with pytest.raises(gl_mod.gl.vm.UserError, match="SHA-256 integrity mismatch"):
        contract.audit_epoch("epoch-bad-hash")


if __name__ == "__main__":
    test_utc_parser_and_pinned_artifact_validation()
    test_excerpt_line_expansion_and_id_boundary_check()
    test_end_to_end_sample_dataset_audit()
    test_ongoing_outage_and_incomplete_accounting()
    test_sha256_mismatch_halts_audit()
    print("[PASS] All 5 SlaErrorBudgetAuditor test suites succeeded.")
