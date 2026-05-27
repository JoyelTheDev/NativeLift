"""Recovery report generator.

After ``class-rebuilder`` produces the output jar, this module
generates a self-contained HTML report summarising:

- Total methods discovered, successfully recovered, and still stubbed.
- Per-class breakdown with expandable rows.
- Warnings emitted by the lifter for each method.
- A colour-coded confidence badge per method.

The report is a single ``<report>.html`` file with inline CSS and JS —
no external dependencies.
"""

from __future__ import annotations

import html
import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _collect(manifest_path: Path, recovered_dir: Path) -> list[dict]:
    """Return a list of class records with recovery status per method."""
    manifest: dict = {}
    if manifest_path and manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Index recovered*.json by (owner, name, desc) -> record
    recovered: dict[tuple[str, str, str], dict] = {}
    if recovered_dir and recovered_dir.exists():
        for p in sorted(recovered_dir.glob("*.json")):
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            key = (rec.get("owner", "?"), rec.get("name", "?"), rec.get("desc", "?"))
            recovered[key] = rec

    classes: list[dict] = []
    for cls in manifest.get("classes", []):
        cname = cls.get("name", "?")
        methods: list[dict] = []
        for m in cls.get("methods", []):
            mname = m.get("name", "?")
            mdesc = m.get("desc", "?")
            key   = (cname, mname, mdesc)
            rec   = recovered.get(key)
            if rec is None:
                status     = "stub"
                confidence = "none"
                warnings   = []
                insn_count = 0
                source     = "—"
            else:
                insns = rec.get("instructions", [])
                warns = rec.get("warnings", [])
                conf  = rec.get("confidence", "low")
                src   = rec.get("source", "?")
                # A method that only has a synthetic RETURN is still a stub.
                non_trivial = [i for i in insns
                               if i.get("op") not in ("RETURN", "ACONST_NULL",
                                                        "ARETURN", "ICONST_0",
                                                        "IRETURN")]
                status     = "recovered" if non_trivial else "stub"
                confidence = conf
                warnings   = warns
                insn_count = len(insns)
                source     = src
            methods.append({
                "name": mname, "desc": mdesc,
                "status": status, "confidence": confidence,
                "warnings": warnings, "insn_count": insn_count,
                "source": source,
            })
        total     = len(methods)
        recovered_n = sum(1 for m in methods if m["status"] == "recovered")
        classes.append({
            "name": cname,
            "total": total,
            "recovered": recovered_n,
            "stubbed": total - recovered_n,
            "methods": methods,
        })
    return classes


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_CSS = """
body{font-family:system-ui,sans-serif;margin:0;padding:1rem 2rem;background:#f4f4f8;color:#1a1a2e}
h1{margin-bottom:.25rem}
.subtitle{color:#666;margin-bottom:1.5rem;font-size:.95rem}
.summary{display:flex;gap:1.5rem;margin-bottom:1.5rem}
.card{background:#fff;border-radius:8px;padding:1rem 1.5rem;box-shadow:0 1px 4px rgba(0,0,0,.1);min-width:120px;text-align:center}
.card .val{font-size:2rem;font-weight:700}
.card .lbl{font-size:.8rem;color:#666;margin-top:.2rem}
.card.good .val{color:#16a34a}
.card.warn .val{color:#d97706}
.card.bad  .val{color:#dc2626}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:2rem}
th{background:#1e293b;color:#fff;text-align:left;padding:.6rem .9rem;font-size:.85rem}
tr.cls-row td{padding:.55rem .9rem;cursor:pointer;border-top:1px solid #e2e8f0;font-weight:600}
tr.cls-row:hover td{background:#f1f5f9}
tr.mth-row td{padding:.4rem .9rem .4rem 2rem;font-size:.85rem;border-top:1px solid #f1f5f9;background:#fafafa}
tr.mth-row.hidden{display:none}
.badge{display:inline-block;border-radius:9999px;padding:.1rem .55rem;font-size:.75rem;font-weight:600}
.b-ok{background:#dcfce7;color:#16a34a}
.b-stub{background:#fee2e2;color:#dc2626}
.b-med{background:#fef9c3;color:#92400e}
.bar-wrap{width:100%;background:#e2e8f0;border-radius:4px;height:8px;display:inline-block}
.bar-fill{height:8px;border-radius:4px;background:#16a34a;display:block}
details summary{cursor:pointer;color:#555;font-size:.78rem}
pre{background:#f8fafc;border-radius:4px;padding:.5rem;font-size:.75rem;max-height:120px;overflow:auto;margin:.3rem 0 0}
"""

_JS = """
document.querySelectorAll('tr.cls-row').forEach(row=>{
  row.addEventListener('click',()=>{
    const id=row.dataset.cls;
    document.querySelectorAll('.mth-row-'+id).forEach(r=>r.classList.toggle('hidden'));
  });
});
"""


def _badge(status: str) -> str:
    if status == "recovered":
        return '<span class="badge b-ok">✔ recovered</span>'
    return '<span class="badge b-stub">✘ stub</span>'


def _conf_badge(conf: str) -> str:
    colours = {"high": "b-ok", "medium": "b-med", "low": "b-stub", "none": "b-stub"}
    cls = colours.get(conf, "b-stub")
    return f'<span class="badge {cls}">{html.escape(conf)}</span>'


def _bar(recovered: int, total: int) -> str:
    pct = int(100 * recovered / total) if total else 0
    return (
        f'<span class="bar-wrap">'
        f'<span class="bar-fill" style="width:{pct}%"></span>'
        f'</span> {recovered}/{total}'
    )


def generate_report(
    manifest_path: Path,
    recovered_dir: Path,
    output_path: Path,
    title: str = "NativeLift — Recovery Report",
) -> None:
    """Write a self-contained HTML report to *output_path*."""
    classes = _collect(manifest_path, recovered_dir)

    total_methods   = sum(c["total"]     for c in classes)
    total_recovered = sum(c["recovered"] for c in classes)
    total_stub      = sum(c["stubbed"]   for c in classes)
    pct = int(100 * total_recovered / total_methods) if total_methods else 0

    rows: list[str] = []
    for i, cls in enumerate(classes):
        cid = f"c{i}"
        recovery_pct = int(100 * cls["recovered"] / cls["total"]) if cls["total"] else 0
        rows.append(
            f'<tr class="cls-row" data-cls="{cid}">'
            f'<td>{html.escape(cls["name"])}</td>'
            f'<td>{_bar(cls["recovered"], cls["total"])}</td>'
            f'<td>{recovery_pct}%</td>'
            f'<td>{cls["stubbed"]}</td>'
            f'</tr>'
        )
        for m in cls["methods"]:
            warn_html = ""
            if m["warnings"]:
                items = "".join(f"<li>{html.escape(w)}</li>" for w in m["warnings"])
                warn_html = (
                    f'<details><summary>{len(m["warnings"])} warning(s)</summary>'
                    f'<pre><ul>{items}</ul></pre></details>'
                )
            rows.append(
                f'<tr class="mth-row mth-row-{cid} hidden">'
                f'<td>{html.escape(m["name"])}<br>'
                f'<code style="font-size:.75rem;color:#64748b">{html.escape(m["desc"])}</code></td>'
                f'<td>{_badge(m["status"])} {warn_html}</td>'
                f'<td>{_conf_badge(m["confidence"])}</td>'
                f'<td>{html.escape(m["source"])} · {m["insn_count"]} insns</td>'
                f'</tr>'
            )

    table_body = "\n".join(rows)

    good_cls = "good" if pct >= 70 else ("warn" if pct >= 40 else "bad")
    stub_cls = "bad" if total_stub > total_recovered else "warn"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="subtitle">Click a class row to expand its methods.</p>
<div class="summary">
  <div class="card {good_cls}">
    <div class="val">{pct}%</div>
    <div class="lbl">recovery rate</div>
  </div>
  <div class="card good">
    <div class="val">{total_recovered}</div>
    <div class="lbl">recovered</div>
  </div>
  <div class="card {stub_cls}">
    <div class="val">{total_stub}</div>
    <div class="lbl">stubbed</div>
  </div>
  <div class="card">
    <div class="val">{total_methods}</div>
    <div class="lbl">total methods</div>
  </div>
  <div class="card">
    <div class="val">{len(classes)}</div>
    <div class="lbl">classes</div>
  </div>
</div>
<table>
<thead>
  <tr>
    <th>Class</th><th>Recovery</th><th>Rate</th><th>Stubs</th>
  </tr>
</thead>
<tbody>
{table_body}
</tbody>
</table>
<script>{_JS}</script>
</body>
</html>
"""
    output_path.write_text(html_doc, encoding="utf-8")
