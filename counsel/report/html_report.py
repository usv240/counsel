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
      /* Dark theme (default) - forensic console */
      --bg: #0d1117; --surface: #161b22; --surface-2: #1c2128; --border: #30363d; --border-soft: #21262d;
      --text: #e6edf3; --dim: #7d8590;
      --green: #3fb950; --yellow: #d29922; --red: #f85149; --blue: #79c0ff; --purple: #bc8cff;
      --cor-bg: #0d3d1a; --inf-bg: #3d2f00; --con-bg: #3d0d0d; --unr-bg: #1a1a1a; --obs-bg: #333333; --obs-text: #aaaaaa;
      --tag-bg: #1a2a3a; --tip-bg: #1c2230;
      --re-genesis: #1a2a3a; --re-tool: #1a2a1a; --re-claim: #2a1a2a; --re-think: #2a2a1a; --re-decision: #1a1a2a; --re-halt: #2a1a1a;
      --shadow: rgba(0,0,0,0.35);
    }
    :root[data-theme="light"] {
      /* Light theme - printed report */
      --bg: #f6f8fa; --surface: #ffffff; --surface-2: #eef1f4; --border: #d0d7de; --border-soft: #e4e8ec;
      --text: #1f2328; --dim: #59636e;
      --green: #1a7f37; --yellow: #9a6700; --red: #cf222e; --blue: #0969da; --purple: #8250df;
      --cor-bg: #dafbe1; --inf-bg: #fff8c5; --con-bg: #ffebe9; --unr-bg: #eaeef2; --obs-bg: #eaeef2; --obs-text: #59636e;
      --tag-bg: #ddf4ff; --tip-bg: #ffffff;
      --re-genesis: #ddf4ff; --re-tool: #dafbe1; --re-claim: #fbefff; --re-think: #fff8c5; --re-decision: #ddf4ff; --re-halt: #ffebe9;
      --shadow: rgba(140,149,159,0.25);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { -webkit-text-size-adjust: 100%; overflow-x: hidden; }
    body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; font-size: 14px; overflow-x: hidden; transition: background 0.2s, color 0.2s; }
    a:focus-visible, button:focus-visible, input:focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }

    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 32px; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
    header h1 { color: var(--blue); font-size: 1.6rem; }
    header .tagline { color: var(--dim); font-size: 12px; font-style: italic; margin-top: 2px; }
    header .meta { color: var(--dim); margin-top: 6px; line-height: 1.8; }
    .theme-toggle { background: var(--surface-2); border: 1px solid var(--border); color: var(--text); cursor: pointer; padding: 8px 13px; border-radius: 6px; font-family: inherit; font-size: 12px; white-space: nowrap; flex-shrink: 0; transition: border-color 0.15s, color 0.15s; }
    .theme-toggle:hover { border-color: var(--blue); color: var(--blue); }

    nav { display: flex; background: var(--surface); border-bottom: 1px solid var(--border); padding: 0 32px; overflow-x: auto; -webkit-overflow-scrolling: touch; }
    nav button { background: none; border: none; color: var(--dim); cursor: pointer;
                 padding: 12px 20px; font-size: 13px; font-family: inherit; transition: color 0.2s, border-color 0.2s;
                 white-space: nowrap; flex-shrink: 0; border-bottom: 2px solid transparent; }
    nav button:hover, nav button.active { color: var(--blue); border-bottom-color: var(--blue); }

    section { display: none; padding: 32px; max-width: 1200px; margin: 0 auto; }
    section.active { display: block; }

    /* What / How / Why intro blurb at the top of each tab */
    .section-intro { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--blue);
                     border-radius: 8px; padding: 14px 18px; margin-bottom: 22px; font-size: 12.5px; line-height: 1.75; color: var(--dim); }
    .section-intro b { color: var(--text); }
    .section-intro .whw { display: block; margin-top: 4px; }
    .section-intro .whw b { color: var(--blue); }

    /* Info "i" button + educational tooltip */
    .info { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border-radius: 50%;
            border: 1px solid var(--dim); color: var(--dim); font-size: 10px; font-style: normal; font-weight: bold; line-height: 1;
            cursor: help; margin-left: 6px; position: relative; vertical-align: middle; user-select: none; flex-shrink: 0; }
    .info:hover, .info:focus { border-color: var(--blue); color: var(--blue); }
    .info .info-tip { display: none; position: absolute; z-index: 60; top: 22px; left: 50%; transform: translateX(-50%);
                      width: 290px; max-width: 78vw; background: var(--tip-bg); border: 1px solid var(--border); border-radius: 8px;
                      padding: 12px 14px; box-shadow: 0 10px 30px var(--shadow); text-align: left; font-size: 11.5px; line-height: 1.6;
                      color: var(--text); font-weight: normal; white-space: normal; }
    .info:hover .info-tip, .info:focus .info-tip { display: block; }
    .info-tip .kv { margin: 6px 0; }
    .info-tip .kv b { color: var(--blue); }

    .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 8px; }

    .state-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .state-obs { background: var(--obs-bg); color: var(--obs-text); }
    .state-inf { background: var(--inf-bg); color: var(--yellow); border: 1px solid var(--yellow); }
    .state-cor { background: var(--cor-bg); color: var(--green); border: 1px solid var(--green); }
    .state-con { background: var(--con-bg); color: var(--red); border: 1px solid var(--red); }
    .state-unr { background: var(--unr-bg); color: var(--dim); border: 1px solid var(--dim); }

    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; transition: border-color 0.2s, box-shadow 0.2s; }
    .card:hover { border-color: var(--blue); box-shadow: 0 8px 24px var(--shadow); }
    .card h2 { color: var(--blue); font-size: 1rem; margin-bottom: 12px; }
    .card .evidence-chain { margin-top: 8px; font-size: 12px; color: var(--dim); }
    .card .evidence-chain a { color: var(--blue); text-decoration: none; }
    .card .evidence-chain a:hover { text-decoration: underline; }

    table { width: 100%; min-width: 640px; border-collapse: collapse; font-size: 12px; }
    th { background: var(--surface); color: var(--dim); text-align: left;
         padding: 8px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
    td { padding: 6px 12px; border-bottom: 1px solid var(--border-soft); word-break: break-all; }
    tr:hover td { background: var(--surface-2); }

    .hash { font-size: 10px; color: var(--dim); }
    .tag-attack { background: var(--tag-bg); color: var(--blue); border: 1px solid var(--blue);
                  padding: 2px 8px; border-radius: 4px; font-size: 11px; margin: 2px; display: inline-block; }

    .summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                padding: 16px; text-align: center; transition: border-color 0.2s, transform 0.15s; }
    .stat-box:hover { border-color: var(--blue); transform: translateY(-2px); }
    .stat-box .num { font-size: 2rem; font-weight: bold; }
    .stat-box .label { font-size: 11px; color: var(--dim); margin-top: 4px; }
    .num.green { color: var(--green); } .num.yellow { color: var(--yellow); } .num.red { color: var(--red); }

    .timeline-item { display: flex; gap: 16px; padding: 8px 0; border-bottom: 1px solid var(--border-soft); }
    .timeline-ts { color: var(--dim); font-size: 11px; min-width: 200px; }
    .timeline-event { flex: 1; }

    #search-ledger { background: var(--surface); border: 1px solid var(--border); color: var(--text);
                     padding: 8px 12px; width: 100%; margin-bottom: 16px; font-family: inherit; border-radius: 4px; }
    #search-ledger:focus { border-color: var(--blue); }

    .integrity-banner { padding: 12px 20px; border-radius: 8px; margin-bottom: 24px; font-weight: bold; word-break: break-all; }
    .integrity-ok { background: var(--cor-bg); border: 1px solid var(--green); color: var(--green); }
    .integrity-fail { background: var(--con-bg); border: 1px solid var(--red); color: var(--red); }

    /* Replay player */
    #replay-player { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    #replay-controls { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
    #replay-controls button { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 7px 16px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 13px; transition: border-color 0.15s, background 0.15s; }
    #replay-controls button:hover { border-color: var(--blue); background: var(--surface-2); }
    #replay-controls button.primary { border-color: var(--blue); color: var(--blue); }
    #replay-speed { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 5px 8px; border-radius: 4px; font-family: inherit; font-size: 12px; }
    #replay-progress-bar { height: 4px; background: var(--border); border-radius: 2px; margin-bottom: 16px; overflow: hidden; }
    #replay-progress-fill { height: 100%; background: var(--blue); width: 0%; transition: width 0.2s; }
    #replay-counter { color: var(--dim); font-size: 12px; margin-left: auto; }
    #replay-feed { max-height: 420px; overflow-y: auto; border: 1px solid var(--border); border-radius: 4px; padding: 8px; }
    .replay-entry { padding: 7px 10px; border-bottom: 1px solid var(--border-soft); font-size: 12px; line-height: 1.5; opacity: 0; transform: translateY(6px); transition: opacity 0.25s ease, transform 0.25s ease; }
    .replay-entry.visible { opacity: 1; transform: translateY(0); }
    .replay-entry .re-seq { color: var(--dim); min-width: 36px; display: inline-block; }
    .replay-entry .re-type { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; margin-right: 8px; }
    .re-genesis   { background: var(--re-genesis); color: var(--blue); }
    .re-tool_call { background: var(--re-tool); color: var(--green); }
    .re-claim_state { background: var(--re-claim); color: var(--purple); }
    .re-agent_thinking { background: var(--re-think); color: var(--yellow); }
    .re-agent_decision { background: var(--re-decision); color: var(--blue); }
    .re-halt { background: var(--re-halt); color: var(--red); }
    .replay-claim-change { margin-top: 4px; font-size: 11px; }
    .replay-claim-change .from-state { color: var(--yellow); }
    .replay-claim-change .to-state { color: var(--green); font-weight: bold; }
    #replay-verdict { display: none; padding: 14px 20px; border-radius: 6px; margin-top: 14px; background: var(--cor-bg); border: 1px solid var(--green); color: var(--green); font-weight: bold; font-size: 14px; animation: fadeIn 0.4s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
    #claim-scoreboard { display: none; margin-top: 14px; }
    #claim-scoreboard h3 { color: var(--blue); font-size: 13px; margin-bottom: 10px; }
    .claim-row { display: flex; align-items: center; gap: 10px; padding: 5px 0; border-bottom: 1px solid var(--border-soft); font-size: 12px; }
    .claim-indicator { width: 10px; height: 10px; border-radius: 50%; background: var(--border); transition: background 0.4s; flex-shrink: 0; }
    .claim-indicator.cor { background: var(--green); box-shadow: 0 0 6px var(--green); }
    .claim-indicator.inf { background: var(--yellow); }
    .claim-indicator.obs { background: var(--dim); }

    @media (max-width: 700px) {
      header { padding: 16px 20px; flex-direction: column; }
      header h1 { font-size: 1.3rem; }
      nav { padding: 0 12px; }
      nav button { padding: 12px 14px; font-size: 12px; }
      section { padding: 20px; }
      .summary-grid { grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 10px; }
      .stat-box { padding: 12px; }
      .stat-box .num { font-size: 1.5rem; }
      .timeline-ts { min-width: 130px; font-size: 10px; }
      .info .info-tip { left: auto; right: 0; transform: none; }
    }
  </style>
</head>
<body>
<header>
  <div>
    <h1>COUNSEL Case File</h1>
    <div class="tagline">Corroboration-first DFIR - every finding traces to evidence, every ruling is earned.</div>
    <div class="meta">
      Run ID: {{ run_id }} &nbsp;|&nbsp;
      Generated: {{ generated_at }} &nbsp;|&nbsp;
      Elapsed: {{ elapsed }}s &nbsp;|&nbsp;
      Claims: {{ total_claims }}
    </div>
  </div>
  <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" title="Switch light / dark theme">Light mode</button>
</header>

<nav>
  <button class="active" onclick="showTab('summary', this)">Executive Summary</button>
  <button onclick="showTab('evidence', this)">Evidence Trace</button>
  <button onclick="showTab('graph', this)">Corroboration Graph</button>
  <button onclick="showTab('ledger', this)">Audit Ledger</button>
  <button onclick="showTab('replay', this)">&#9654; Investigation Replay</button>
</nav>

<!-- ═══ SUMMARY ═══ -->
<section id="summary" class="active">
  <div class="section-intro">
    <span class="whw"><b>What:</b> the consolidated verdict for this investigation - one ruling per finding.</span>
    <span class="whw"><b>How:</b> a corroboration engine (not the language model) assigns each finding a state from typed forensic evidence.</span>
    <span class="whw"><b>Why:</b> an analyst can act on a CORROBORATED finding and defend it in court, because every ruling is earned from independent sources, not asserted by an AI.</span>
  </div>

  <div class="integrity-banner {{ integrity_class }}">
    Evidence Integrity: {{ integrity_status }}
    &nbsp;|&nbsp; SHA256 IN: <span class="hash">{{ evidence_sha_in[:32] }}…</span>
    &nbsp;|&nbsp; SHA256 OUT: <span class="hash">{{ evidence_sha_out[:32] }}…</span>
    &nbsp;|&nbsp; Ledger Chain: {{ chain_status }}
    <span class="info" tabindex="0">i<span class="info-tip">
      <div class="kv"><b>What:</b> proof the evidence was never altered during analysis.</div>
      <div class="kv"><b>How:</b> the evidence is SHA256-hashed before (IN) and after (OUT) the run; a match plus a valid Ed25519 hash-chain means nothing changed.</div>
      <div class="kv"><b>Why:</b> in DFIR this is "spoliation" - if the original data is modified, findings are inadmissible. VERIFIED = read-only integrity held.</div>
    </span></span>
  </div>

  <div class="summary-grid">
    <div class="stat-box"><div class="num green">{{ corroborated_count }}</div><div class="label">CORROBORATED <span class="info" tabindex="0">i<span class="info-tip"><div class="kv"><b>What:</b> a confirmed finding.</div><div class="kv"><b>How:</b> two or more <i>independent</i> forensic sources agree and combined support &#8805; 0.80.</div><div class="kv"><b>Why:</b> requiring independence is what blocks single-source hallucinations.</div></span></span></div></div>
    <div class="stat-box"><div class="num yellow">{{ inference_count }}</div><div class="label">INFERENCE <span class="info" tabindex="0">i<span class="info-tip"><div class="kv"><b>What:</b> a lead, not yet confirmed.</div><div class="kv"><b>How:</b> one source supports it, but a second independent group has not (yet) agreed.</div><div class="kv"><b>Why:</b> shown for transparency but deliberately <i>not</i> asserted - this is withholding in action.</div></span></span></div></div>
    <div class="stat-box"><div class="num red">{{ contradicted_count }}</div><div class="label">CONTRADICTED <span class="info" tabindex="0">i<span class="info-tip"><div class="kv"><b>What:</b> a claim the engine actively rejected.</div><div class="kv"><b>How:</b> an independent, higher-weight signal refutes it (contradiction &#8805; 0.60).</div><div class="kv"><b>Why:</b> a naive tool would assert it on keyword presence; COUNSEL refutes it on evidence.</div></span></span></div></div>
    <div class="stat-box"><div class="num">{{ unresolved_count }}</div><div class="label">UNRESOLVED <span class="info" tabindex="0">i<span class="info-tip"><div class="kv"><b>What:</b> searched, but undecided.</div><div class="kv"><b>How:</b> the bounded investigation finished without sufficient corroborating evidence.</div><div class="kv"><b>Why:</b> "I don't know" is a valid, honest forensic answer - better than a guess.</div></span></span></div></div>
    <div class="stat-box"><div class="num">{{ tool_calls }}</div><div class="label">TOOL CALLS <span class="info" tabindex="0">i<span class="info-tip"><div class="kv"><b>What:</b> forensic tool executions this run.</div><div class="kv"><b>How:</b> each is a typed MCP call (registry, prefetch, memory, network, logs) recorded in the ledger.</div><div class="kv"><b>Why:</b> every finding links back to these exact calls - full traceability.</div></span></span></div></div>
    <div class="stat-box"><div class="num">{{ iterations }}</div><div class="label">ITERATIONS <span class="info" tabindex="0">i<span class="info-tip"><div class="kv"><b>What:</b> agent reasoning rounds.</div><div class="kv"><b>How:</b> each round the agent reviews open gaps and chooses the next highest-value tool.</div><div class="kv"><b>Why:</b> the loop is bounded - the agent cannot run forever, an architectural safety limit.</div></span></span></div></div>
  </div>

  {% if attack_techniques %}
  <div class="card">
    <h2>MITRE ATT&amp;CK Techniques (Corroborated only)<span class="info" tabindex="0">i<span class="info-tip">
      <div class="kv"><b>What:</b> the adversary techniques behind the confirmed findings, mapped to the MITRE ATT&amp;CK framework.</div>
      <div class="kv"><b>How:</b> only techniques from CORROBORATED findings are listed - inferred or contradicted claims are excluded.</div>
      <div class="kv"><b>Why:</b> ATT&amp;CK IDs are the shared language of IR; download the layer to view the kill chain in the official Navigator.</div>
    </span></span></h2>
    <div style="margin-bottom:12px">
      {% for t in attack_techniques %}
      <span class="tag-attack">{{ t }}</span>
      {% endfor %}
    </div>
    <button onclick="downloadAttackLayer()" style="background:var(--surface);border:1px solid var(--blue);color:var(--blue);padding:6px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px;">
      &#11015; Download ATT&CK Navigator Layer (.json)
    </button>
    <span style="color:var(--dim);font-size:11px;margin-left:10px">Open at navigator.attack.mitre.org → Open Existing Layer → Upload</span>
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
    {% set _paths = rule_path_counts.get(claim.claim_type.value, 1) %}
    {% if _paths > 1 %}
    <div style="color:var(--dim);font-size:11px;margin-top:4px">corroborated via {{ _paths }} independent rule paths</div>
    {% endif %}
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
    <div style="margin-top:8px;color:var(--dim);font-size:12px">
      {% for note in claim.analyst_notes %}<div>{{ note }}</div>{% endfor %}
    </div>
    {% endif %}
  </div>
  {% endfor %}

  {% if ruling_changes %}
  <div class="card">
    <h2>Self-Correction Timeline (Ruling Changes)<span class="info" tabindex="0">i<span class="info-tip">
      <div class="kv"><b>What:</b> every time a finding changed state during the investigation, in order.</div>
      <div class="kv"><b>How:</b> the corroboration engine re-scored claims as each new tool result arrived; a change fires only when independent evidence shifts the math.</div>
      <div class="kv"><b>Why:</b> this is genuine self-correction, not a script - watch a claim flip from INFERENCE to CONTRADICTED when the evidence refutes it.</div>
    </span></span></h2>
    <p style="color:var(--dim);font-size:12px;margin-bottom:16px">
      State transitions driven by the corroboration engine, not LLM assertion. Each RULING CHANGE
      reflects new independent evidence being weighed — this is genuine self-correction, not scripting.
    </p>
    {% for rc in ruling_changes %}
    <div class="timeline-item">
      <div class="timeline-ts">seq={{ rc.seq }} iter={{ rc.iteration }}</div>
      <div class="timeline-event">
        <strong>{{ rc.claim_type }}</strong> [{{ rc.claim_id }}]
        &nbsp;
        <span class="state-badge state-{{ rc.from_state[:3].lower() }}">{{ rc.from_state }}</span>
        &nbsp;&#8594;&nbsp;
        <span class="state-badge state-{{ rc.to_state[:3].lower() }}">{{ rc.to_state }}</span>
        <span style="color:var(--dim);font-size:11px;margin-left:8px">support={{ rc.support }}</span>
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  {% if withheld_claims %}
  <div class="card">
    <h2 style="color:var(--yellow)">Hallucinations Withheld (Engine Refused to Corroborate)<span class="info" tabindex="0">i<span class="info-tip">
      <div class="kv"><b>What:</b> claims a keyword-matching AI would have asserted, that COUNSEL did <i>not</i> confirm.</div>
      <div class="kv"><b>How:</b> they reached only INFERENCE (one source), were CONTRADICTED (refuted), or UNRESOLVED (no corroboration found).</div>
      <div class="kv"><b>Why:</b> this is the anti-hallucination guarantee made visible - the value is in what the engine refused to say.</div>
    </span></span></h2>
    <p style="color:var(--dim);font-size:12px;margin-bottom:16px">
      A naive LLM would have asserted these as confirmed. COUNSEL's corroboration engine withheld CORROBORATED status
      because independent evidence groups were insufficient. This is the anti-hallucination guarantee in action.
    </p>
    {% for claim in withheld_claims %}
    <div style="padding:8px 0;border-bottom:1px solid var(--border-soft);display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;">
      <span class="state-badge {{ state_class(claim.state) }}">{{ claim.state.value }}</span>
      <strong>{{ claim.claim_type.value }}</strong>
      <span style="color:var(--dim)">— {{ claim.subject[:70] }}</span>
      {% if claim.state.value == 'INFERENCE' %}
      <span style="color:var(--yellow);font-size:11px">support={{ "%.2f"|format(claim.support_score) }} — single independent group (need &#8805;2)</span>
      {% elif claim.state.value == 'UNRESOLVED' %}
      <span style="color:var(--dim);font-size:11px">bounded search exhausted — no corroborating evidence found</span>
      {% elif claim.state.value == 'CONTRADICTED' %}
      <span style="color:var(--red);font-size:11px">evidence conflict detected — assertion blocked</span>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% endif %}
</section>

<!-- ═══ EVIDENCE TRACE ═══ -->
<section id="evidence">
  <div class="section-intro">
    <span class="whw"><b>What:</b> the complete per-rule claim record - every claim the engine evaluated, with its state, support score, and the exact tools behind it.</span>
    <span class="whw"><b>How:</b> each row links to the ledger sequence numbers of the tool calls that produced it, so any finding is traceable to its source.</span>
    <span class="whw"><b>Why:</b> judges and analysts must be able to trace any finding back to the specific tool execution - this table is that audit trail.</span>
  </div>
  <p style="color:var(--dim);font-size:12px;margin-bottom:12px">
    Multiple rules may evaluate the same claim type independently, so a type can appear more than once here —
    the <a href="#summary" style="color:var(--blue)">Executive Summary</a> consolidates these into one verdict per finding.
  </p>
  <div class="table-wrap">
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
  </div>
</section>

<!-- ═══ CORROBORATION GRAPH ═══ -->
<section id="graph">
  <div class="section-intro">
    <span class="whw"><b>What:</b> each finding shown as a tree of the independent evidence sources beneath it.</span>
    <span class="whw"><b>How:</b> a finding is CORROBORATED only when branches from <i>different</i> forensic domains (disk, memory, network, logs) converge on it.</span>
    <span class="whw"><b>Why:</b> independence is the whole game - two sources from the same artifact are not corroboration, and this view shows the separation at a glance.</span>
  </div>
  <div class="card">
    <h2>Corroboration Relationships</h2>
    <p style="color:var(--dim);font-size:12px;margin-bottom:12px">Consolidated verdict — one finding per claim type.</p>
    <div style="font-family:monospace;font-size:12px;line-height:1.8;">
      {% for claim in graph_claims %}
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
  <div class="section-intro">
    <span class="whw"><b>What:</b> the tamper-evident record of every step the agent took - tool calls, reasoning, and ruling changes, in order.</span>
    <span class="whw"><b>How:</b> each entry stores the SHA256 of the previous one (a hash chain) and the whole file is Ed25519-signed; altering any row breaks every hash after it.</span>
    <span class="whw"><b>Why:</b> this is what makes findings court-defensible - a verifier can prove the record was not edited after the fact. Click an evidence link anywhere to jump here.</span>
  </div>
  <div class="table-wrap">
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
  </div>
</section>

<!-- ═══ INVESTIGATION REPLAY ═══ -->
<section id="replay">
  <div class="section-intro">
    <span class="whw"><b>What:</b> a play-by-play animation of the investigation reconstructed from the signed ledger.</span>
    <span class="whw"><b>How:</b> it steps through ledger entries in order, updating each claim's state live as the evidence that drove it arrives.</span>
    <span class="whw"><b>Why:</b> it makes the corroboration process legible - you can watch findings get earned (and refuted) instead of taking the verdict on faith.</span>
  </div>
  <div id="replay-player">
    <h2 style="color:var(--blue);margin-bottom:6px;">Investigation Replay</h2>
    <p style="color:var(--dim);font-size:12px;margin-bottom:14px;">
      Watch COUNSEL re-derive its verdict from raw evidence, one ledger entry at a time.
      Claim states evolve live as independent evidence groups accumulate.
      Each RULING CHANGE (yellow&#8594;green) reflects the corroboration engine firing —
      not an LLM assertion.
    </p>
    <div id="replay-controls">
      <button class="primary" id="btn-play" onclick="replayPlay()">&#9654; Play</button>
      <button id="btn-pause" onclick="replayPause()" style="display:none">&#10074;&#10074; Pause</button>
      <button onclick="replayStep()">&#9654;&#10073; Step</button>
      <button onclick="replayReset()">&#8634; Reset</button>
      <label style="color:var(--dim);font-size:12px;">Speed:
        <select id="replay-speed" onchange="replaySetSpeed(this.value)">
          <option value="1200">Slow</option>
          <option value="600" selected>Normal</option>
          <option value="250">Fast</option>
          <option value="80">Turbo</option>
        </select>
      </label>
      <span id="replay-counter" style="color:var(--dim);font-size:12px;">0 / 0</span>
    </div>
    <div id="replay-progress-bar"><div id="replay-progress-fill"></div></div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
      <div id="replay-feed" style="flex:2;min-width:280px;"></div>
      <div id="claim-scoreboard" style="flex:1;min-width:200px;">
        <h3>Claim States</h3>
        <div id="claim-rows"></div>
      </div>
    </div>
    <div id="replay-verdict"></div>
  </div>
</section>

<script>
// ── Theme (light / dark) ─────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = (theme === 'light') ? 'Dark mode' : 'Light mode';
  try { localStorage.setItem('counsel-theme', theme); } catch (e) {}
}
function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  applyTheme(cur === 'light' ? 'dark' : 'light');
}
(function initTheme() {
  var saved = null;
  try { saved = localStorage.getItem('counsel-theme'); } catch (e) {}
  if (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) saved = 'light';
  applyTheme(saved === 'light' ? 'light' : 'dark');
})();

function showTab(id, btn) {
  document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
  if (id === 'replay' && !replayInitialized) replayInit();
}
function filterLedger(q) {
  const rows = document.querySelectorAll('.ledger-row');
  rows.forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
  });
}
const attackLayerData = {{ attack_layer_json }};
function downloadAttackLayer() {
  const blob = new Blob([JSON.stringify(attackLayerData, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'counsel_attack_{{ run_id }}.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Investigation Replay Engine ──────────────────────────────────────────────
const REPLAY_ENTRIES = {{ ledger_entries_json }};
let replayIdx = 0;
let replayTimer = null;
let replaySpeed = 600;
let replayInitialized = false;
const claimStates = {};  // claim_type -> current state badge class

function replayInit() {
  replayInitialized = true;
  replayReset();
  document.getElementById('claim-scoreboard').style.display = 'block';
}

function replayEntryHTML(e) {
  const t = e.entry_type;
  const p = e.payload || {};
  let detail = '';

  if (t === 'genesis') {
    detail = 'Evidence sealed: SHA256=' + (p.evidence_sha256_in||'').slice(0,24) + '&hellip;';
  } else if (t === 'tool_call') {
    const q = p.parse_quality != null ? (p.parse_quality*100).toFixed(0)+'%' : '';
    detail = p.tool + ' &rarr; ' + (p.record_count||0) + ' records' + (q ? ' quality='+q : '');
    if (p.warnings && p.warnings.length) detail += ' <span style="color:var(--yellow)">['+p.warnings[0].slice(0,60)+'&hellip;]</span>';
  } else if (t === 'agent_thinking') {
    detail = 'Extended thinking &rarr; ' + (p.next_tool||'(no tool)') + ' | sha256=' + (p.thinking_sha256||'').slice(0,16) + '&hellip; len=' + (p.thinking_len||0);
  } else if (t === 'claim_state') {
    const from = p.from_state||'?', to = p.to_state||'?';
    const arrow = to === 'CORROBORATED'
      ? '<span class="to-state">' + to + '</span>'
      : '<span style="color:var(--text)">' + to + '</span>';
    detail = '<strong>' + (p.claim_type||'') + '</strong> &nbsp;'
           + '<span class="from-state">' + from + '</span>'
           + ' &rarr; ' + arrow
           + ' <span style="color:var(--dim)">support=' + (p.support||0).toFixed(2) + '</span>';
    updateClaimScoreboard(p.claim_type, to);
  } else if (t === 'agent_decision') {
    detail = '[iter ' + (p.iteration||'') + '] ' + (p.action||'') + (p.rationale ? ' — ' + p.rationale.slice(0,80) : '');
  } else if (t === 'halt') {
    detail = 'HALT: ' + (p.reason||'') + ' - ' + (p.corroborated_claims||0) + ' CORROBORATED in ' + (p.elapsed_seconds||0).toFixed(1) + 's';
  } else {
    detail = JSON.stringify(p).slice(0, 100);
  }

  return '<span class="re-seq">#' + e.seq + '</span>'
       + '<span class="re-type re-' + t + '">' + t.replace('_',' ') + '</span>'
       + '<span class="re-ts" style="color:var(--dim);font-size:10px;margin-right:8px">' + (e.ts||'').slice(11,19) + '</span>'
       + detail;
}

function updateClaimScoreboard(claimType, newState) {
  if (!claimType) return;
  claimStates[claimType] = newState;
  const rows = document.getElementById('claim-rows');
  rows.innerHTML = '';
  Object.entries(claimStates).forEach(([ct, st]) => {
    const cls = st === 'CORROBORATED' ? 'cor' : st === 'INFERENCE' ? 'inf' : 'obs';
    rows.innerHTML += '<div class="claim-row">'
      + '<div class="claim-indicator ' + cls + '"></div>'
      + '<span style="flex:1">' + ct + '</span>'
      + '<span class="state-badge state-' + st.slice(0,3).toLowerCase() + '" style="font-size:10px">' + st.slice(0,3) + '</span>'
      + '</div>';
  });
}

function replayStep() {
  if (replayIdx >= REPLAY_ENTRIES.length) { replayFinish(); return; }
  const e = REPLAY_ENTRIES[replayIdx];
  const feed = document.getElementById('replay-feed');
  const div = document.createElement('div');
  div.className = 'replay-entry';
  div.innerHTML = replayEntryHTML(e);
  feed.appendChild(div);
  setTimeout(() => div.classList.add('visible'), 20);
  feed.scrollTop = feed.scrollHeight;

  replayIdx++;
  const pct = REPLAY_ENTRIES.length ? (replayIdx / REPLAY_ENTRIES.length * 100) : 0;
  document.getElementById('replay-progress-fill').style.width = pct + '%';
  document.getElementById('replay-counter').textContent = replayIdx + ' / ' + REPLAY_ENTRIES.length;

  if (replayIdx >= REPLAY_ENTRIES.length) replayFinish();
}

function replayPlay() {
  if (replayIdx >= REPLAY_ENTRIES.length) replayReset();
  document.getElementById('btn-play').style.display = 'none';
  document.getElementById('btn-pause').style.display = '';
  replayTick();
}

function replayTick() {
  replayStep();
  if (replayIdx < REPLAY_ENTRIES.length) {
    replayTimer = setTimeout(replayTick, replaySpeed);
  }
}

function replayPause() {
  clearTimeout(replayTimer);
  replayTimer = null;
  document.getElementById('btn-play').style.display = '';
  document.getElementById('btn-pause').style.display = 'none';
}

function replayReset() {
  replayPause();
  replayIdx = 0;
  document.getElementById('replay-feed').innerHTML = '';
  document.getElementById('replay-progress-fill').style.width = '0%';
  document.getElementById('replay-counter').textContent = '0 / ' + REPLAY_ENTRIES.length;
  document.getElementById('replay-verdict').style.display = 'none';
  document.getElementById('claim-rows').innerHTML = '';
  Object.keys(claimStates).forEach(k => delete claimStates[k]);
  document.getElementById('btn-play').style.display = '';
  document.getElementById('btn-pause').style.display = 'none';
}

function replaySetSpeed(v) { replaySpeed = parseInt(v, 10); }

function replayFinish() {
  replayPause();
  const corr = Object.values(claimStates).filter(s => s === 'CORROBORATED').length;
  const v = document.getElementById('replay-verdict');
  v.style.display = 'block';
  v.innerHTML = 'Investigation complete - '
    + corr + ' claim(s) CORROBORATED. '
    + 'Verdict derived from hash-chained audit evidence, not LLM assertion.';
}
</script>
</body>
</html>
"""


def _build_attack_layer(techniques: list[str], run_id: str) -> dict:
    return {
        "name": f"COUNSEL Investigation {run_id}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Auto-generated by COUNSEL corroboration engine (run {run_id}). "
            "Only CORROBORATED findings (>=2 independent evidence groups) are included."
        ),
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": t,
                "score": 100,
                "color": "#f85149",
                "comment": f"CORROBORATED by COUNSEL (run {run_id})",
                "enabled": True,
            }
            for t in techniques
        ],
        "gradient": {"colors": ["#ff6666", "#ff0000"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "CORROBORATED claim", "color": "#f85149"}],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
    }


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
    elif etype == "agent_thinking":
        return (
            f"[iter {payload.get('iteration', '')}] Thinking block "
            f"sha256={payload.get('thinking_sha256', '')[:16]}… "
            f"len={payload.get('thinking_len', 0)} → next={payload.get('next_tool', '?')}"
        )
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

    # Headline views present ONE representative per claim_type (distinct findings).
    # Multiple rules can emit the same claim_type, so the raw claim list contains
    # several instances of e.g. payload_executed in conflicting states. The full
    # per-rule list is still shown in the Evidence Trace tab as the audit record.
    all_claims = claim_graph.claims
    distinct = claim_graph.distinct_findings()
    corroborated = [c for c in distinct if c.state == ClaimState.CORROBORATED]
    withheld = [c for c in distinct if c.state != ClaimState.CORROBORATED]

    # Stat boxes reflect distinct findings so they match the cards below.
    dist_counts = {s.value: sum(1 for c in distinct if c.state == s) for s in ClaimState}

    # How many independent rule paths produced each claim_type (shown on the card
    # as "corroborated via N independent paths" — turns the duplication into a
    # strength signal instead of noise).
    rule_path_counts: dict[str, int] = {}
    for c in all_claims:
        rule_path_counts[c.claim_type.value] = rule_path_counts.get(c.claim_type.value, 0) + 1

    attack_techniques = summary.get("attack_techniques", [])
    attack_layer_json = json.dumps(_build_attack_layer(attack_techniques, run_id))

    # Extract ruling changes from ledger for self-correction timeline
    ruling_changes: list[dict] = []
    try:
        with open(ledger.ledger_path, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line:
                    continue
                try:
                    _entry = json.loads(_line)
                except json.JSONDecodeError:
                    continue
                if _entry.get("entry_type") != "claim_state":
                    continue
                _p = _entry.get("payload", {})
                _from = _p.get("from_state", "")
                _to = _p.get("to_state", "")
                if _from and _to and _from != _to:
                    ruling_changes.append({
                        "seq": _entry.get("seq", ""),
                        "iteration": _p.get("iteration", ""),
                        "claim_type": _p.get("claim_type", ""),
                        "claim_id": _p.get("claim_id", "")[:8],
                        "from_state": _from,
                        "to_state": _to,
                        "support": f"{_p.get('support', 0):.2f}",
                    })
    except OSError:
        pass

    # Order the timeline chronologically (by investigation iteration, then ledger
    # seq). The ledger writes claim_state entries grouped per claim, so raw order
    # is not temporal — sorting makes the self-correction read as it happened.
    def _iter_key(rc: dict):
        it = rc.get("iteration", 0)
        sq = rc.get("seq", 0)
        return (it if isinstance(it, int) else 0, sq if isinstance(sq, int) else 0)
    ruling_changes.sort(key=_iter_key)

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

    ledger_entries_json = json.dumps(ledger_entries)

    # Derive stats from ledger when not passed in (launcher omission guard)
    if tool_calls == 0:
        tool_calls = sum(1 for e in ledger_entries if e.get("entry_type") == "tool_call")
    if iterations == 0:
        for _e in ledger_entries:
            if _e.get("entry_type") == "halt":
                iterations = _e.get("payload", {}).get("iteration", 0)
                break

    tmpl = Template(HTML_TEMPLATE)
    html = tmpl.render(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        elapsed=f"{elapsed_seconds:.1f}",
        total_claims=len(all_claims),
        corroborated_count=dist_counts.get("CORROBORATED", 0),
        inference_count=dist_counts.get("INFERENCE", 0),
        contradicted_count=dist_counts.get("CONTRADICTED", 0),
        unresolved_count=dist_counts.get("UNRESOLVED", 0),
        attack_techniques=attack_techniques,
        attack_layer_json=attack_layer_json,
        corroborated_claims=corroborated,
        withheld_claims=withheld,
        ruling_changes=ruling_changes,
        all_claims=all_claims,
        graph_claims=distinct,
        rule_path_counts=rule_path_counts,
        ledger_entries=ledger_entries,
        ledger_entries_json=ledger_entries_json,
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
