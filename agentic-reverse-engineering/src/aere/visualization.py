"""Self-contained offline HTML reports for bounded Android/Steam analysis."""

from __future__ import annotations

import html
import json
import re
from typing import Any


_CSS = """
:root{color-scheme:dark;--bg:#0b1020;--panel:#131b2e;--panel2:#18233a;--line:#2b3956;--text:#eef3ff;--muted:#a8b4cc;--accent:#78e3cf;--amber:#ffd27a;--red:#ff9d9d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0%,#172540 0,transparent 34rem),var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1440px;margin:auto;padding:34px 24px 64px}header{border:1px solid var(--line);border-radius:22px;padding:28px;background:linear-gradient(135deg,#18233a,#111a2b);box-shadow:0 18px 55px #0005}
h1{font-size:clamp(28px,4vw,44px);line-height:1.1;margin:0 0 10px;letter-spacing:-.03em}p{color:var(--muted);margin:6px 0}.eyebrow{color:var(--accent);font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;margin:18px 0 28px}.card,.section{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:16px}.card{padding:16px}.card span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.card strong{display:block;font-size:22px;margin-top:4px;overflow-wrap:anywhere}.toolbar{position:sticky;top:0;z-index:5;background:#0b1020ed;backdrop-filter:blur(10px);padding:12px 0}.toolbar input{width:min(100%,520px);background:var(--panel);border:1px solid var(--line);border-radius:10px;color:var(--text);padding:11px 14px;font:inherit}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,560px),1fr));gap:16px}.section{padding:18px;min-width:0}.section h2{font-size:18px;margin:0 0 12px}.table-wrap{overflow:auto;max-height:520px;border-radius:10px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere;max-width:460px}th{position:sticky;top:0;background:#1b2943;color:#bceee4;font-size:11px;text-transform:uppercase;letter-spacing:.06em}tr:hover td{background:#ffffff08}.empty{color:var(--muted);font-style:italic}.badges{display:flex;flex-wrap:wrap;gap:8px}.badge{border:1px solid var(--line);border-radius:999px;padding:5px 10px;background:var(--panel2);font-size:12px}.status{color:var(--accent);font-weight:700}.notice{margin:12px 0;padding:11px 13px;border-left:3px solid var(--amber);background:#332c1d66;color:#f3dfb3;border-radius:6px}.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}.preview{background:var(--panel2);border:1px solid var(--line);border-radius:12px;overflow:hidden}.preview img{display:block;width:100%;height:170px;object-fit:contain;background:#080c15}.preview div{padding:9px;font-size:12px;overflow-wrap:anywhere;color:var(--muted)}.coverage{display:flex;flex-wrap:wrap;gap:8px}.coverage-item{border:1px solid var(--line);padding:8px 10px;border-radius:10px;background:var(--panel2);font-size:12px}.coverage-item b{display:block;color:var(--accent);margin-top:2px}.limitations li{margin:7px 0;color:#c6d0e3}.foot{margin-top:26px;padding-top:14px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
@media(max-width:600px){main{padding:16px 12px 42px}header{padding:20px}.section{padding:14px}th,td{padding:7px}}
"""

_SCRIPT = """
const q=document.getElementById('filter');
q.addEventListener('input',()=>{const needle=q.value.toLocaleLowerCase();document.querySelectorAll('table tbody tr').forEach(row=>{row.hidden=!row.textContent.toLocaleLowerCase().includes(needle);});});
"""


def _text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return html.escape(str(value), quote=True)


def _table(rows: list[Any], empty: str | None = None) -> str:
    if not rows:
        return f'<p class="empty">{_text(empty or "No rows.")}</p>'
    if all(not isinstance(row, dict) for row in rows):
        rows = [{"value": row} for row in rows]
    headers: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            for key in row:
                if key not in headers:
                    headers.append(str(key))
    head = "".join(f"<th scope=\"col\">{_text(name.replace('_', ' '))}</th>" for name in headers)
    body_rows = []
    for row in rows:
        mapping = row if isinstance(row, dict) else {"value": row}
        cells = "".join(f"<td>{_text(mapping.get(key))}</td>" for key in headers)
        body_rows.append(f"<tr>{cells}</tr>")
    return f'<div class="table-wrap"><table class="data-table"><thead><tr>{head}</tr></thead><tbody>{"".join(body_rows)}</tbody></table></div>'


def render_offline_html(report: dict[str, Any]) -> str:
    """Render report data with escaped text and only embedded raster-image URIs."""
    title = _text(report.get("title") or "AERE analysis report")
    subtitle = _text(report.get("subtitle") or "Bounded local analysis")
    kind = _text(report.get("kind") or "analysis")
    summary_cards = []
    for item in report.get("summary", []):
        summary_cards.append(
            f'<div class="card"><span>{_text(item.get("label"))}</span><strong>{_text(item.get("value"))}</strong></div>'
        )

    coverage = report.get("coverage", {})
    coverage_html = "".join(
        f'<div class="coverage-item">{_text(key)}<b>{_text(value)}</b></div>'
        for key, value in coverage.items()
    )

    sections_html = []
    for section in report.get("sections", []):
        name = _text(section.get("title") or "Analysis")
        sections_html.append(
            f'<section class="section"><h2>{name}</h2>{_table(section.get("rows", []), section.get("empty"))}</section>'
        )

    candidates = report.get("engine_candidates", [])
    engine_html = ""
    if candidates:
        badges = []
        for candidate in candidates:
            label = candidate.get("engine", "engine candidate")
            status = candidate.get("status", "candidate")
            signals = candidate.get("signal_count")
            extra = f" · {signals} marker(s)" if signals is not None else ""
            badges.append(f'<span class="badge">{_text(label)} · {_text(status)}{_text(extra)}</span>')
        engine_html = f'<section class="section"><h2>Engine markers — candidates only</h2><div class="badges">{"".join(badges)}</div><p>These file markers do not establish engine version, title compatibility, or runtime behavior.</p></section>'

    previews = []
    for item in report.get("previews", []):
        uri = str(item.get("data_uri", ""))
        if not re.fullmatch(r"data:image/(?:png|jpeg|gif|webp|bmp);base64,[A-Za-z0-9+/=]+", uri):
            continue
        previews.append(
            f'<article class="preview"><img loading="lazy" src="{html.escape(uri, quote=True)}" alt="{_text(item.get("name"))}"><div>{_text(item.get("name"))}<br>{_text(item.get("size"))} bytes · {_text(item.get("mime_type"))}</div></article>'
        )
    gallery_html = ""
    if previews:
        gallery_html = f'<section class="section"><h2>Local image previews</h2><div class="gallery">{"".join(previews)}</div></section>'

    limitations = report.get("limitations", [])
    limitation_html = ""
    if limitations:
        limitation_html = '<section class="section"><h2>Coverage limits</h2><ul class="limitations">' + "".join(f"<li>{_text(item)}</li>" for item in limitations) + "</ul></section>"

    notices = []
    if report.get("inventory_truncated"):
        notices.append("The install inventory hit a configured limit or skipped files. Do not treat this report as complete coverage.")
    notices.extend(str(item) for item in report.get("notices", []))
    truncated_notice = "".join(f'<div class="notice">{_text(item)}</div>' for item in notices)

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<title>{title} — AERE</title><style>{_CSS}</style></head>
<body><main><header><div class="eyebrow">AERE · {_text(kind)} · Offline report</div><h1>{title}</h1><p>{subtitle}</p>{truncated_notice}<div class="coverage" style="margin-top:14px">{coverage_html}</div></header>
<div class="summary">{"".join(summary_cards)}</div><div class="toolbar"><input id="filter" type="search" placeholder="Filter tables by name, path, permission, or value…" aria-label="Filter report tables"></div>
<div class="grid">{engine_html}{''.join(sections_html)}{gallery_html}{limitation_html}</div>
<footer class="foot">Generated locally by AERE. No external scripts, stylesheets, fonts, or network requests are required. This report is static evidence and does not prove runtime behavior or compatibility beyond its stated scope.</footer></main><script>{_SCRIPT}</script></body></html>"""
    return document
