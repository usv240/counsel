"""
COUNSEL Static HTML Case File Generator.

Produces a self-contained HTML file (no web server required) from the
ClaimGraph and ledger. Works offline - judges can open it in any browser.

Four views (tab-based, pure HTML/CSS/JS):
  1. Executive Summary - verdict, ATT&CK techniques, key timeline
  2. Evidence Trace - every claim linked to its exact ledger entry and tool call
  3. Corroboration Graph - visual claim graph (SVG/CSS, no external libraries)
  4. Audit Ledger - full hash-chained ledger in a searchable table

WCAG-AA accessible: high contrast, semantic HTML, no color-only information.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from ..engine.model import ClaimGraph, ClaimState
from ..ledger.ledger import Ledger

STATE_CLASSES = {
    ClaimState.OBSERVED:     "state-obs",
    ClaimState.INFERENCE:    "state-inf",
    ClaimState.CORROBORATED: "state-cor",
    ClaimState.CONTRADICTED: "state-con",
    ClaimState.UNRESOLVED:   "state-unr",
}

STATE_LABELS = {
    ClaimState.OBSERVED:     "OBSERVED",
    ClaimState.INFERENCE:    "INFERENCE",
    ClaimState.CORROBORATED: "CORROBORATED",
    ClaimState.CONTRADICTED: "CONTRADICTED",
    ClaimState.UNRESOLVED:   "UNRESOLVED",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>COUNSEL Case File - {{ run_id }}</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --dim: #7d8590;
      --green: #3fb950; --yellow: #d29922; --red: #f85149;
      --blue: #79c0ff; --purple: #bc8cff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; font-size: 14px; }

    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 32px; }
    header h1 { color: var(--blue); font-size: 1.6rem; }
    header .meta { color: var(--dim); margin-top: 4px; }

    nav { display: flex; background: var(--surface); border-bottom: 1px solid var(--border); padding: 0 32px; }
    nav button { background: none; border: none; color: var(--dim); cursor: pointer;
                 padding: 12px 20px; font-size: 13px; font-family: inherit; transition: color 0.2s; }
    nav button:hover, nav button.active { color: var(--blue); border-bottom: 2px solid var(--blue); }

    section { display: none; padding: 32px; max-width: 1200px; margin: 0 auto; }
    section.active { display: block; }

    .state-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .state-obs { background: #333; color: #aaa; }
    .state-inf { background: #3d2f00; color: #d29922; border: 1px solid #d29922; }
    .state-cor { background: #0d3d1a; color: #3fb950; border: 1px solid #3fb950; }
    .state-con { background: #3d0d0d; color: #f85149; border: 1px solid #f85149; }
    .state-unr { background: #1a1a1a; color: #7d8590; border: 1px solid #7d8590; }

    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
    .card h2 { color: var(--blue); font-size: 1rem; margin-bottom: 12px; }
    .card .evidence-chain { margin-top: 8px; font-size: 12px; color: var(--dim); }
    .card .evidence-chain a { color: var(--blue); text-decoration: none; }
    .card .evidence-chain a:hover { text-decoration: underline; }

    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { background: var(--surface); color: var(--dim); text-align: left;
         padding: 8px 12px; border-bottom: 1px solid var(--border); }
    td { padding: 6px 12px; border-bottom: 1px solid #21262d; word-break: break-all; }
    tr:hover td { background: #1c2128; }

    .hash { font-size: 10px; color: var(--dim); }
    .tag-attack { background: #1a2a3a; color: var(--blue); border: 1px solid var(--blue);
                  padding: 2px 8px; border-radius: 4px; font-size: 11px; margin: 2px; display: inline-block; }

    .summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                padding: 16px; text-align: center; }
    .stat-box .num { font-size: 2rem; font-weight: bold; }
    .stat-box .label { font-size: 11px; color: var(--dim); margin-top: 4px; }
    .num.green { color: var(--green); } .num.yellow { color: var(--yellow); } .num.red { color: var(--red); }

    .timeline-item { display: flex; gap: 16px; padding: 8px 0; border-bottom: 1px solid #21262d; }
    .timeline-ts { color: var(--dim); font-size: 11px; min-width: 200px; }
    .timeline-event { flex: 1; }

    #search-ledger { background: var(--surface); border: 1px solid var(--border); color: var(--text);
                     padding: 8px 12px; width: 100%; margin-bottom: 16px; font-family: inherit; border-radius: 4px; }

    .integrity-banner { padding: 12px 20px; border-radius: 8px; margin-bottom: 24px; font-weight: bold; }
    .integrity-ok { background: #0d3d1a; border: 1px solid var(--green); color: var(--green); }
    .integrity-fail { background: #3d0d0d; border: 1px solid var(--red); color: var(--red); }
  </style>
</head>
<body>
<header>
  <h1>COUNSEL Case File</h1>
  <div class="meta">
    Run ID: {{ run_id }} &nbsp;|&nbsp;
    Generated: {{ generated_at }} &nbsp;|&nbsp;
    Elapsed: {{ elapsed }}s &nbsp;|&nbsp;
    Claims: {{ total_claims }}
  </div>
</header>

<nav>
  <button class="active" onclick="showTab('summary', this)">Executive Summary</button>
  <button onclick="showTab('evidence', this)">Evidence Trace</button>
  <button onclick="showTab('graph', this)">Corroboration Graph</button>
  <button onclick="showTab('ledger', this)">Audit Ledger</button>
</nav>

<!-- ═══ SUMMARY ═══ -->
<section id="summary" class="active">
  <div class="integrity-banner {{ integrity_class }}">
    Evidence Integrity: {{ integrity_status }}
    &nbsp;|&nbsp; SHA256 IN: <span class="hash">{{ evidence_sha_in[:32] }}…</span>
    &nbsp;|&nbsp; SHA256 OUT: <span class="hash">{{ evidence_sha_out[:32] }}…</span>
    &nbsp;|&nbsp; Ledger Chain: {{ chain_status }}
  </div>

  <div class="summary-grid">
    <div class="stat-box"><div class="num green">{{ corroborated_count }}</div><div class="label">CORROBORATED</div></div>
    <div class="stat-box"><div class="num yellow">{{ inference_count }}</div><div class="label">INFERENCE</div></div>
    <div class="stat-box"><div class="num red">{{ contradicted_count }}</div><div class="label">CONTRADICTED</div></div>
    <div class="stat-box"><div class="num">{{ unresolved_count }}</div><div class="label">UNRESOLVED</div></div>
    <div class="stat-box"><div class="num">{{ tool_calls }}</div><div class="label">TOOL CALLS</div></div>
    <div class="stat-box"><div class="num">{{ iterations }}</div><div class="label">ITERATIONS</div></div>
  </div>

  {% if attack_techniques %}
  <div class="card">
    <h2>MITRE ATT&CK Techniques (Corroborated)</h2>
    {% for t in attack_techniques %}
    <span class="tag-attack">{{ t }}</span>
    {% endfor %}
  </div>
  {% endif %}

  {% for claim in corroborated_claims %}
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h2>{{ claim.claim_type.value }}</h2>
      <span class="state-badge state-cor">CORROBORATED</span>
    </div>
    <div><strong>Subject:</strong> {{ claim.subject }}</div>
    <div style="margin-top:8px"><strong>Confidence:</strong> {{ "%.2f"|format(claim.support_score) }}</div>
    {% if claim.attack_technique %}
    <div><span class="tag-attack">{{ claim.attack_technique.value }}</span></div>
    {% endif %}
    <div class="evidence-chain">
      <strong>Evidence chain:</strong>
      {% for ev in claim.evidence %}
      <a href="#ledger-seq-{{ ev.ledger_seq }}">
        seq={{ ev.ledger_seq }} {{ ev.tool }} (w={{ "%.2f"|format(ev.weight) }})
      </a>
      {% if not loop.last %} + {% endif %}
      {% endfor %}
    </div>
    {% if claim.analyst_notes %}
    <div style="margin-top:8px;color:#7d8590;font-size:12px">
      {% for note in claim.analyst_notes %}<div>{{ note }}</div>{% endfor %}
    </div>
    {% endif %}
  </div>
  {% endfor %}
</section>

<!-- ═══ EVIDENCE TRACE ═══ -->
<section id="evidence">
  <table>
    <tr><th>ID</th><th>Claim Type</th><th>Subject</th><th>State</th><th>Support</th><th>Tool Evidence</th><th>History</th></tr>
    {% for claim in all_claims %}
    <tr>
      <td>{{ claim.id }}</td>
      <td>{{ claim.claim_type.value }}</td>
      <td>{{ claim.subject[:50] }}</td>
      <td><span class="state-badge {{ state_class(claim.state) }}">{{ claim.state.value }}</span></td>
      <td>{{ "%.2f"|format(claim.support_score) }}</td>
      <td>
        {% for ev in claim.evidence %}
        <a href="#ledger-seq-{{ ev.ledger_seq }}" style="color:var(--blue);font-size:11px;">
          [{{ ev.tool }} seq={{ ev.ledger_seq }}]
        </a>
        {% endfor %}
      </td>
      <td>{{ claim.history|length }} changes</td>
    </tr>
    {% endfor %}
  </table>
</section>

<!-- ═══ CORROBORATION GRAPH ═══ -->
<section id="graph">
  <div class="card">
    <h2>Corroboration Relationships</h2>
    <div style="font-family:monospace;font-size:12px;line-height:1.8;">
      {% for claim in all_claims %}
      {% set color_class = state_class(claim.state) %}
      <div>
        <span class="state-badge {{ color_class }}">{{ claim.state.value[:3] }}</span>
        &nbsp;<strong>{{ claim.claim_type.value }}</strong> - {{ claim.subject[:60] }}
        <br>
        {% for ev in claim.evidence %}
        &nbsp;&nbsp;&nbsp;└─ <span style="color:var(--blue)">{{ ev.tool }}</span>
               <span style="color:var(--dim)">seq={{ ev.ledger_seq }} w={{ "%.2f"|format(ev.weight) }}</span>
        <br>
        {% endfor %}
      </div>
      <br>
      {% endfor %}
    </div>
  </div>
</section>

<!-- ═══ AUDIT LEDGER ═══ -->
<section id="ledger">
  <input id="search-ledger" type="text" placeholder="Search ledger entries..." oninput="filterLedger(this.value)">
  <table id="ledger-table">
    <tr><th>Seq</th><th>Type</th><th>Timestamp</th><th>Summary</th><th>Hash</th></tr>
    {% for entry in ledger_entries %}
    <tr id="ledger-seq-{{ entry.seq }}" class="ledger-row">
      <td>{{ entry.seq }}</td>
      <td>{{ entry.entry_type }}</td>
      <td>{{ entry.ts[:19] }}</td>
      <td style="font-size:11px;">{{ entry_summary(entry) }}</td>
      <td class="hash">{{ entry.entry_hash[:16] }}…</td>
    </tr>
    {% endfor %}
  </table>
</section>

<script>
function showTab(id, btn) {
  document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}
function filterLedger(q) {
  const rows = document.querySelectorAll('.ledger-row');
  rows.forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""


def _entry_summary(entry: dict) -> str:
    etype = entry.get("entry_type", "")
    payload = entry.get("payload", {})
    if etype == "genesis":
        return f"Evidence SHA256: {payload.get('evidence_sha256_in', '')[:20]}…"
    elif etype == "tool_call":
        return f"{payload.get('tool', '')} → {payload.get('record_count', 0)} records, quality={payload.get('parse_quality', 0):.0%}"
    elif etype == "claim_state":
        return (
            f"{payload.get('claim_type', '')} [{payload.get('claim_id', '')}]: "
            f"{payload.get('from_state', '')} → {payload.get('to_state', '')} "
            f"(support={payload.get('support', 0):.2f})"
        )
    elif etype == "agent_decision":
        return f"[iter {payload.get('iteration', '')}] {payload.get('action', '')} - {payload.get('rationale', '')[:60]}"
    elif etype == "halt":
        return f"HALT: {payload.get('reason', '')} - {payload.get('corroborated_claims', 0)} corroborated"
    return json.dumps(payload)[:80]


def generate(
    claim_graph: ClaimGraph,
    ledger: Ledger,
    output_path: Path,
    run_id: str,
    elapsed_seconds: float,
    evidence_sha_in: str = "",
    evidence_sha_out: str = "",
    chain_valid: bool = True,
    tool_calls: int = 0,
    iterations: int = 0,
) -> Path:
    """Generate a self-contained HTML Case File."""
    summary = claim_graph.investigation_summary()

    corroborated = claim_graph.corroborated_claims()
    all_claims = claim_graph.claims

    integrity_match = evidence_sha_in and evidence_sha_in == evidence_sha_out
    integrity_class = "integrity-ok" if (integrity_match and chain_valid) else "integrity-fail"
    integrity_status = "VERIFIED" if (integrity_match and chain_valid) else "CHECK FAILED"

    # Read ledger entries
    ledger_entries = []
    try:
        with open(ledger.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ledger_entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass

    tmpl = Template(HTML_TEMPLATE)
    html = tmpl.render(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        elapsed=f"{elapsed_seconds:.1f}",
        total_claims=len(all_claims),
        corroborated_count=summary["state_distribution"].get("CORROBORATED", 0),
        inference_count=summary["state_distribution"].get("INFERENCE", 0),
        contradicted_count=summary["state_distribution"].get("CONTRADICTED", 0),
        unresolved_count=summary["state_distribution"].get("UNRESOLVED", 0),
        attack_techniques=summary.get("attack_techniques", []),
        corroborated_claims=corroborated,
        all_claims=all_claims,
        ledger_entries=ledger_entries,
        evidence_sha_in=evidence_sha_in,
        evidence_sha_out=evidence_sha_out,
        integrity_class=integrity_class,
        integrity_status=integrity_status,
        chain_status="VALID" if chain_valid else "INVALID",
        tool_calls=tool_calls,
        iterations=iterations,
        state_class=lambda s: STATE_CLASSES.get(s, "state-unr"),
        entry_summary=_entry_summary,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html.replace("%Human", "%H"), encoding="utf-8")
    return output_path
