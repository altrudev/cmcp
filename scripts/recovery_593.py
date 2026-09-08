"""Apply the bounded cMCP #593 repair to a clean checkout.

Recovery artifact only. Refuses unknown source shapes and does not modify
files until all preconditions have passed.
"""
from __future__ import annotations

import argparse
import ast
import difflib
from pathlib import Path

SOURCE = Path('src/cmcp_verify/verify.py')
TEST = Path('tests/unit/test_verify_audit_bundle_malformed_shapes.py')
OLD = '''    failures: list[str] = []
    entries = bundle_json.get("entries", [])
    if not entries:
        return AuditBundleResult(verified=False, entry_count=0, failures=["bundle has no entries"])
'''
NEW = '''    # #593: establish external JSON container shapes before interpretation.
    # Missing fields retain their existing diagnostics; malformed values do not.
    if not isinstance(bundle_json, dict):
        return _audit_bundle_shape_failure("bundle")
    entries = bundle_json.get("entries", [])
    if not isinstance(entries, list):
        return _audit_bundle_shape_failure("bundle.entries")
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return _audit_bundle_shape_failure(f"bundle.entries[{i}]", len(entries))

    if claim_json is not None:
        if not isinstance(claim_json, dict):
            return _audit_bundle_shape_failure("claim", len(entries))
        # Only the objects consumed by the optional binding checks are required.
        for path in (
            ("gateway",),
            ("gateway", "audit_chain"),
            ("gateway", "call_summary"),
            ("trace",),
            ("trace", "tool_transcript"),
            ("trace", "cnf"),
            ("trace", "cnf", "jwk"),
        ):
            obj: Any = claim_json
            for depth, name in enumerate(path):
                if name not in obj:
                    break
                obj = obj[name]
                if not isinstance(obj, dict):
                    return _audit_bundle_shape_failure(
                        "claim." + ".".join(path[:depth + 1]), len(entries)
                    )

    failures: list[str] = []
    if not entries:
        return AuditBundleResult(verified=False, entry_count=0, failures=["bundle has no entries"])
'''
HELPER = '''def _audit_bundle_shape_failure(path: str, entry_count: int = 0) -> AuditBundleResult:
    """Classify malformed external structure without interpreting its contents."""
    return AuditBundleResult(
        verified=False,
        entry_count=entry_count,
        failures=[f"{path} has invalid object or array shape"],
    )


'''

def transform(source: str) -> str:
    if source.count(OLD) != 1:
        raise ValueError('Expected verifier entry anchor not found exactly once')
    tree = ast.parse(source)
    functions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    names = [n.name for n in functions]
    if names.count('verify_audit_bundle') != 1 or '_audit_bundle_shape_failure' in names:
        raise ValueError('Unexpected verifier structure or already applied repair')
    target = next(n for n in functions if n.name == 'verify_audit_bundle')
    lines = source.splitlines(keepends=True)
    start, end = target.lineno - 1, target.end_lineno
    body = ''.join(lines[start:end])
    if body.count(OLD) != 1:
        raise ValueError('Anchor is not inside the expected function')
    updated = ''.join(lines[:start]) + HELPER + body.replace(OLD, NEW, 1) + ''.join(lines[end:])
    ast.parse(updated)
    return updated

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Write the verified transformation')
    args = parser.parse_args()
    source = SOURCE.read_text()
    updated = transform(source)
    before = source.splitlines(keepends=True)
    after = updated.splitlines(keepends=True)
    diff = ''.join(difflib.unified_diff(before, after, fromfile='a/' + str(SOURCE), tofile='b/' + str(SOURCE)))
    if not args.apply:
        print(diff)
        return
    if not TEST.exists():
        raise SystemExit('Missing original #593 regression file; refusing partial installation')
    if 'pytest.xfail' not in TEST.read_text():
        raise SystemExit('Expected original reproducer not found; refusing unknown test history')
    SOURCE.write_text(updated)
    print(diff)
    print('Applied source guard; convert the original xfails to ordinary assertions before release.')

if __name__ == '__main__':
    main()
