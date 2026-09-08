"""Isolated, non-mutating validation of the #593 recovery transformer."""
from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/cmcp_verify/verify.py"
spec = importlib.util.spec_from_file_location("recovery_593", ROOT / "scripts/recovery_593.py")
assert spec is not None and spec.loader is not None
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
original = importlib.import_module("cmcp_verify.verify")
source = SOURCE.read_text()
updated = recovery.transform(source)
module = ast.parse(updated)
selected = [
    node for node in module.body
    if isinstance(node, ast.FunctionDef)
    and node.name in {"_audit_bundle_shape_failure", "verify_audit_bundle"}
]
assert len(selected) == 2
namespace: dict[str, Any] = dict(vars(original))
compiled_module = ast.fix_missing_locations(
    ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations")],
                level=0,
            ),
            *selected,
        ],
        type_ignores=[],
    )
)
exec(compile(compiled_module, str(SOURCE), "exec"), namespace)
verify = namespace["verify_audit_bundle"]
Result = original.AuditBundleResult


def bundle() -> dict[str, Any]:
    body = {"entry_type": "session", "call_id": "call-1", "prev_entry_hash": "genesis"}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return {"entries": [{**body, "entry_hash": digest}]}


@pytest.mark.parametrize("value", ["bad", 1, True, {"unexpected": "object"}, ["bad"], [1], [True], [[]], [None]])
def test_entries(value: Any) -> None:
    result = verify({"entries": value})
    assert isinstance(result, Result)
    assert result.verified is False and result.failures


@pytest.mark.parametrize("claim", [
    {"gateway": "bad"}, {"gateway": {"audit_chain": "bad"}},
    {"gateway": {"call_summary": "bad"}}, {"trace": "bad"},
    {"trace": {"tool_transcript": "bad"}}, {"trace": {"cnf": "bad"}},
    {"trace": {"cnf": {"jwk": "bad"}}},
])
def test_claims(claim: dict[str, Any]) -> None:
    result = verify(bundle(), claim)
    assert result.verified is False and result.failures
    assert result.entry_count == 1


def test_missing_entries() -> None:
    assert verify({}) == Result(False, 0, ["bundle has no entries"])


def test_valid_entry() -> None:
    assert verify(bundle()) == Result(True, 1, [])


def test_root_boundary() -> None:
    assert verify(None).verified is False
    assert verify(bundle(), "bad").verified is False


def test_unknown_source_refused() -> None:
    with pytest.raises(ValueError):
        recovery.transform(source.replace("    failures: list[str] = []", "    failures = []"))
    with pytest.raises(ValueError):
        recovery.transform(updated)


def test_original_body_preserved() -> None:
    before = ast.parse(source)
    after = ast.parse(updated)
    old_fn = next(node for node in before.body if isinstance(node, ast.FunctionDef) and node.name == "verify_audit_bundle")
    new_fn = next(node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == "verify_audit_bundle")
    old_tail = next(i for i, node in enumerate(old_fn.body) if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "prev" for t in node.targets))
    new_tail = next(i for i, node in enumerate(new_fn.body) if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "prev" for t in node.targets))
    assert ast.dump(ast.Module(body=old_fn.body[old_tail:], type_ignores=[])) == ast.dump(ast.Module(body=new_fn.body[new_tail:], type_ignores=[]))
    assert SOURCE.read_text() == source
