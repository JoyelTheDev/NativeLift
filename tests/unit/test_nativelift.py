"""Fast unit tests for the ast-matcher / lifter stack.

These tests run against the bundled ``tests/fixtures/ghidra-dump-snake.json``
fixture so they don't require Ghidra to be installed.  They validate:

1. Basic JNI call lifting (FindClass → GETFIELD, CallVoidMethod → INVOKEVIRTUAL)
2. The :class:`StackTracker` post-pass produces balanced instruction sequences.
3. The :class:`AArch64Abi` registers correctly without crashing on import.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Add the Python workspace to sys.path so tests run without installing packages.
_REPO_ROOT = Path(__file__).resolve().parents[2]
for _pkg in ("ast_matcher", "binary_introspect", "manifest_merge",
             "j2c_dumper_cli", "snippet_importer"):
    _pkg_root = _REPO_ROOT / "py" / _pkg
    if _pkg_root.exists() and str(_pkg_root) not in sys.path:
        sys.path.insert(0, str(_pkg_root))

FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "ghidra-dump-snake.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lift(code: str, desc: str = "()V"):
    from ast_matcher.lifter.driver import lift_ghidra_function
    from ast_matcher.lifter.options import LifterOptions
    opts = LifterOptions()
    return lift_ghidra_function(code, desc, options=opts)


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------

class TestFixtureLift:
    def test_fixture_exists(self):
        assert FIXTURE.exists(), f"fixture missing: {FIXTURE}"

    def test_getScore_produces_getfield(self):
        data = json.loads(FIXTURE.read_text())
        fn = next(f for f in data["functions"] if f["methodName"] == "getScore")
        result = _lift(fn["code"], fn["methodDesc"])
        ops = [i["op"] for i in result["instructions"]]
        assert "GETFIELD" in ops, f"expected GETFIELD in {ops}"
        assert "IRETURN" in ops, f"expected IRETURN in {ops}"

    def test_move_produces_invokevirtual(self):
        data = json.loads(FIXTURE.read_text())
        fn = next(f for f in data["functions"] if f["methodName"] == "move")
        result = _lift(fn["code"], fn["methodDesc"])
        ops = [i["op"] for i in result["instructions"]]
        assert any(op in ops for op in ("INVOKEVIRTUAL", "INVOKESPECIAL")), \
            f"expected invoke in {ops}"

    def test_stack_tracker_produces_no_underflow(self):
        """The StackTracker post-pass must never leave the stack at negative depth."""
        from ast_matcher.lifter.stack_tracker import StackTracker
        data = json.loads(FIXTURE.read_text())
        for fn in data["functions"]:
            raw = _lift(fn["code"], fn["methodDesc"])
            balanced = StackTracker().process(raw["instructions"], fn["methodDesc"])
            # Simulate a forward depth pass and assert it never goes negative.
            depth = 0
            for ins in balanced:
                from ast_matcher.lifter.stack_tracker import _instruction_effect
                pop_n, push_n = _instruction_effect(ins)
                assert depth >= pop_n, (
                    f"stack underflow in {fn['methodName']}: "
                    f"depth={depth}, need={pop_n}, op={ins['op']}"
                )
                depth = depth - pop_n + push_n


# ---------------------------------------------------------------------------
# StackTracker unit tests
# ---------------------------------------------------------------------------

class TestStackTracker:
    def _track(self, insns, desc="()V"):
        from ast_matcher.lifter.stack_tracker import StackTracker
        warns: list[str] = []
        out = StackTracker().process(insns, desc, warns)
        return out, warns

    def test_no_op_on_balanced_sequence(self):
        insns = [
            {"op": "ACONST_NULL"},
            {"op": "ARETURN"},
        ]
        out, warns = self._track(insns, "()Ljava/lang/Object;")
        assert warns == [], f"unexpected warnings: {warns}"
        assert [i["op"] for i in out] == ["ACONST_NULL", "ARETURN"]

    def test_pads_underflow_before_areturn(self):
        insns = [{"op": "ARETURN"}]
        out, warns = self._track(insns, "()Ljava/lang/Object;")
        ops = [i["op"] for i in out]
        assert "ACONST_NULL" in ops
        assert "ARETURN" in ops

    def test_pads_underflow_before_ireturn(self):
        insns = [{"op": "IRETURN"}]
        out, warns = self._track(insns, "()I")
        ops = [i["op"] for i in out]
        assert "ICONST_0" in ops
        assert "IRETURN" in ops

    def test_pads_before_putfield(self):
        insns = [
            {"op": "PUTFIELD", "owner": "Foo", "name": "x", "desc": "I"},
        ]
        out, warns = self._track(insns)
        ops = [i["op"] for i in out]
        assert ops.index("PUTFIELD") > 0  # something was padded in front

    def test_label_resets_depth(self):
        insns = [
            {"op": "ACONST_NULL"},
            {"op": "GOTO", "target": "L1"},
            {"op": "LABEL", "label": "L1"},
            {"op": "ARETURN"},
        ]
        out, warns = self._track(insns, "()Ljava/lang/Object;")
        ops = [i["op"] for i in out]
        assert "ARETURN" in ops

    def test_invoke_static_no_args(self):
        insns = [
            {"op": "INVOKESTATIC", "owner": "Foo", "name": "bar", "desc": "()V"},
            {"op": "RETURN"},
        ]
        out, warns = self._track(insns)
        assert warns == []
        assert [i["op"] for i in out] == ["INVOKESTATIC", "RETURN"]

    def test_invoke_virtual_pops_receiver_and_args(self):
        # CallVoidMethod: pop this + 2 int args
        insns = [
            {"op": "INVOKEVIRTUAL", "owner": "Foo", "name": "bar", "desc": "(II)V"},
            {"op": "RETURN"},
        ]
        out, warns = self._track(insns)
        ops = [i["op"] for i in out]
        # We need 3 values on stack: receiver + 2 args.
        # With depth=0, tracker inserts 3 ACONST_NULL or ICONST_0 pads.
        assert ops.count("INVOKEVIRTUAL") == 1


# ---------------------------------------------------------------------------
# AArch64 ABI registration test
# ---------------------------------------------------------------------------

class TestAArch64Abi:
    def test_registers_without_crash(self):
        """aarch64_sysv module must import and register cleanly."""
        try:
            from binary_introspect.arch import list_abis
            abis = list_abis()
            # If capstone ARM64 is available, the ABI should be registered.
            try:
                from capstone import CS_ARCH_ARM64
                assert "aarch64-sysv" in abis, \
                    f"aarch64-sysv not in {abis}"
            except ImportError:
                pass  # capstone ARM64 not installed in this env — that's fine.
        except ImportError as exc:
            pytest.skip(f"binary_introspect not importable: {exc}")

    def test_aarch64_not_amd64(self):
        """The aarch64 ABI must not shadow the amd64 ABIs."""
        try:
            from binary_introspect.arch import list_abis
            abis = list_abis()
            assert "amd64-sysv" in abis
            assert "amd64-windows" in abis
        except ImportError as exc:
            pytest.skip(f"binary_introspect not importable: {exc}")


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------

class TestSchemaValidate:
    def test_valid_classes_json(self, tmp_path):
        from j2c_dumper_cli.schema_validate import validate_artifact
        artifact = tmp_path / "classes.json"
        artifact.write_text(
            '{"schemaVersion":1,"classes":[],"loaderClass":null}',
            encoding="utf-8"
        )
        data = validate_artifact(artifact, "classes")
        assert data["schemaVersion"] == 1

    def test_missing_schema_version(self, tmp_path):
        from j2c_dumper_cli.schema_validate import validate_artifact, SchemaError
        artifact = tmp_path / "classes.json"
        artifact.write_text('{"classes":[]}', encoding="utf-8")
        with pytest.raises(SchemaError, match="schemaVersion"):
            validate_artifact(artifact, "classes")

    def test_wrong_schema_version(self, tmp_path):
        from j2c_dumper_cli.schema_validate import validate_artifact, SchemaError
        artifact = tmp_path / "classes.json"
        artifact.write_text('{"schemaVersion":99,"classes":[]}', encoding="utf-8")
        with pytest.raises(SchemaError, match="mismatch"):
            validate_artifact(artifact, "classes")


# ---------------------------------------------------------------------------
# Report generation test
# ---------------------------------------------------------------------------

class TestReportGeneration:
    def test_report_smoke(self, tmp_path):
        from j2c_dumper_cli.report import generate_report
        manifest = tmp_path / "manifest.json"
        manifest.write_text(
            json.dumps({
                "schemaVersion": 1,
                "classes": [
                    {
                        "name": "com/example/Foo",
                        "methods": [
                            {"name": "bar", "desc": "()V", "access": 256}
                        ],
                        "fields": []
                    }
                ]
            }),
            encoding="utf-8"
        )
        recovered = tmp_path / "recovered"
        recovered.mkdir()
        report = tmp_path / "report.html"
        generate_report(manifest, recovered, report)
        html = report.read_text(encoding="utf-8")
        assert "com/example/Foo" in html
        assert "NativeLift" in html


# ---------------------------------------------------------------------------
# Trace merge test
# ---------------------------------------------------------------------------

class TestTraceMerge:
    def test_deduplicates_binds(self, tmp_path):
        from j2c_dumper_cli.trace_merge import merge_traces
        import json as _json
        bind = {"ev": "bind", "class": "Foo", "name": "bar", "sig": "()V"}
        t1 = tmp_path / "trace1.jsonl"
        t2 = tmp_path / "trace2.jsonl"
        t1.write_text(_json.dumps(bind) + "\n", encoding="utf-8")
        t2.write_text(_json.dumps(bind) + "\n", encoding="utf-8")
        out = tmp_path / "merged.jsonl"
        n = merge_traces([t1, t2], out)
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        assert len(lines) == 1, f"expected 1 bind event after dedup, got {len(lines)}"

    def test_includes_all_enter_events(self, tmp_path):
        from j2c_dumper_cli.trace_merge import merge_traces
        import json as _json
        enter1 = {"ev": "enter", "class": "Foo", "name": "bar", "sig": "()V", "thread": 1}
        enter2 = {"ev": "enter", "class": "Foo", "name": "baz", "sig": "()I", "thread": 1}
        t1 = tmp_path / "trace1.jsonl"
        t2 = tmp_path / "trace2.jsonl"
        t1.write_text(_json.dumps(enter1) + "\n", encoding="utf-8")
        t2.write_text(_json.dumps(enter2) + "\n", encoding="utf-8")
        out = tmp_path / "merged.jsonl"
        n = merge_traces([t1, t2], out)
        assert n == 2
