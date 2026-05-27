"""Multi-run trace merger.

When a single ``--run-cmd`` invocation only exercises part of the
obfuscated code (e.g. a server-side jar where only the HTTP path runs),
users can supply multiple ``--run-cmd`` entries and this module merges
all resulting ``trace.jsonl`` files into a single stream.

Merge strategy
--------------
* ``bind`` events are deduplicated by ``(class, name, sig)`` key — we
  keep the first occurrence.
* ``enter`` / ``exit`` event pairs for a given method are included from
  every run that produced them, so branch coverage accumulates across
  runs.
* Events within a run retain their original order.  Across runs, events
  are appended in run order (run 0 first, run N last).

The merged file is a valid ``trace.jsonl`` that ``trace-to-bytecode``
can consume directly.
"""

from __future__ import annotations

import json
from pathlib import Path


def merge_traces(trace_paths: list[Path], output: Path) -> int:
    """Merge one or more ``trace.jsonl`` files into *output*.

    Parameters
    ----------
    trace_paths:
        Paths to individual trace files (one per ``--run-cmd`` run).
    output:
        Destination path for the merged trace.

    Returns
    -------
    Total number of events written.
    """
    seen_binds: set[tuple[str, str, str]] = set()
    lines_written = 0

    with output.open("w", encoding="utf-8") as out_f:
        for path in trace_paths:
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8", errors="replace") as in_f:
                for raw in in_f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        ev = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    ev_type = ev.get("ev")

                    # Deduplicate bind events
                    if ev_type == "bind":
                        key = (
                            ev.get("class", ""),
                            ev.get("name", ""),
                            ev.get("sig", ""),
                        )
                        if key in seen_binds:
                            continue
                        seen_binds.add(key)

                    out_f.write(json.dumps(ev, separators=(",", ":")) + "\n")
                    lines_written += 1

    return lines_written
