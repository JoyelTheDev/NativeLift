"""JSON Schema version enforcement for pipeline artifacts.

Each stage in the NativeLift pipeline produces a versioned JSON artifact.
The ``schemaVersion`` field in each file must match the version declared
in the corresponding ``schemas/*.schema.json``.  Mismatches previously
caused silent wrong output; this module detects them loudly.

Usage::

    from j2c_dumper_cli.schema_validate import validate_artifact, SchemaError

    validate_artifact(path_to_classes_json, "classes")
    # raises SchemaError with a clear message if the version doesn't match
"""

from __future__ import annotations

import json
from pathlib import Path


class SchemaError(ValueError):
    """Raised when an artifact fails schema-version validation."""


# Map artifact kind → schema filename stem and expected schemaVersion.
# These are the versions that ship with NativeLift at release time.
_SCHEMAS: dict[str, tuple[str, int]] = {
    "classes":          ("classes",          1),
    "binary":           ("binary",           1),
    "manifest":         ("manifest",         1),
    "recovered-method": ("recovered-method", 1),
    "trace-event":      ("trace-event",      1),
}


def _schema_dir() -> Path:
    """Locate the repo-level ``schemas/`` directory from this file's path."""
    here = Path(__file__).resolve()
    for ancestor in [here] + list(here.parents):
        candidate = ancestor / "schemas"
        if candidate.is_dir():
            return candidate
        # Also try one level up (handles the py/ sub-tree layout)
        candidate2 = ancestor.parent / "schemas"
        if candidate2.is_dir():
            return candidate2
    raise FileNotFoundError(
        "Could not locate the NativeLift schemas/ directory.  "
        "Run from the project root or set NATIVELIFT_ROOT."
    )


def _expected_version(kind: str) -> int:
    """Return the expected schemaVersion for *kind* from the schema JSON file.

    Falls back to the hard-coded table when the schema file is absent
    (e.g. during unit tests without the full project checkout).
    """
    _, fallback = _SCHEMAS.get(kind, ("unknown", 1))
    try:
        schema_file = _schema_dir() / f"{kind}.schema.json"
        if schema_file.exists():
            data = json.loads(schema_file.read_text(encoding="utf-8"))
            props = data.get("properties") or {}
            sv = props.get("schemaVersion") or {}
            if "const" in sv:
                return int(sv["const"])
            if "enum" in sv:
                return int(max(sv["enum"]))
    except Exception:
        pass
    return fallback


def validate_artifact(path: Path, kind: str) -> dict:
    """Load *path* as JSON and validate its ``schemaVersion``.

    Parameters
    ----------
    path:
        Path to the artifact file.
    kind:
        One of ``"classes"``, ``"binary"``, ``"manifest"``,
        ``"recovered-method"``, ``"trace-event"``.

    Returns
    -------
    The parsed JSON dict.

    Raises
    ------
    SchemaError
        If ``schemaVersion`` is absent or doesn't match the expected value.
    FileNotFoundError
        If *path* doesn't exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError(f"Artifact {path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise SchemaError(f"Artifact {path} is not a JSON object")

    actual  = data.get("schemaVersion")
    expected = _expected_version(kind)

    if actual is None:
        raise SchemaError(
            f"Artifact {path!r} is missing 'schemaVersion' "
            f"(expected {expected} for kind={kind!r})"
        )

    if int(actual) != expected:
        raise SchemaError(
            f"Schema version mismatch for {path!r}: "
            f"got {actual}, expected {expected} (kind={kind!r}).  "
            f"Re-run the producing stage with the current NativeLift version."
        )

    return data


def validate_recovered_dir(recovered_dir: Path) -> list[str]:
    """Validate all ``*.json`` files in *recovered_dir*.

    Returns a list of warning strings for files that fail validation
    (rather than raising, since partial recovery dirs are common).
    """
    warnings: list[str] = []
    for p in sorted(recovered_dir.glob("*.json")):
        try:
            validate_artifact(p, "recovered-method")
        except (SchemaError, FileNotFoundError) as exc:
            warnings.append(str(exc))
    return warnings
