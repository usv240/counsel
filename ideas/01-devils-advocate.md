# Idea 01 — DEVIL'S ADVOCATE

> *"Find Evil" → the **devil**. **Devil's Advocate** = the skeptic that challenges every
> claim before it's believed. The pun IS the methodology.*

## One-liner
An autonomous incident-response agent on the SANS SIFT Workstation that doesn't just
*report* findings — it **builds a court case** against the attacker. Every finding is an
*allegation* that must be backed by *admissible evidence* (a specific artifact + the exact
tool execution that produced it). A second adversarial agent — the **Devil's Advocate /
Defense** — tries to *disprove* every finding before it's allowed into the verdict. That
adversarial cross-examination **is** the self-correction engine.

Methodologically grounded in **Analysis of Competing Hypotheses (ACH)** — a real
intelligence-analysis discipline taught to senior analysts: form a hypothesis, hunt for
evidence that would *break* it, only believe what survives.

## The loop
```
                    ┌─────────────────────────────────────┐
                    │   READ-ONLY MCP SERVER (the bailiff)  │
                    │  exposes typed funcs: get_amcache(),  │
                    │  extract_mft_timeline(), scan_yara()… │
                    │  ✗ no execute_shell  ✗ no write/delete│
                    │  every call → hash-chained ledger     │
                    └─────────────────────────────────────┘
                                    ▲
        ┌──────────────┐   queries  │   evidence    ┌──────────────────┐
        │  PROSECUTOR  │────────────┼──────────────▶│  DEVIL'S ADVOCATE │
        │  builds case │            │               │  attacks the case │
        │  forms       │◀───────────┼───────────────│  competing        │
        │  hypotheses  │  rebuttals │               │  hypotheses (ACH) │
        └──────────────┘            │               └──────────────────┘
                │                    │                        │
                └──────────▶  JUDGE / VERDICT  ◀──────────────┘
                   only findings that survive cross-examination
                   are ruled ADMISSIBLE (with confidence + citation)
```

1. **Prosecutor** runs triage, forms hypotheses (e.g. "initial access via malicious .docm →
   persistence via Run key → C2 over 443").
2. For each claim it must produce an **exhibit**: artifact path/offset + the MCP tool call +
   raw output hash.
3. **Devil's Advocate** cross-examines: is there a benign explanation? Does memory contradict
   the disk timeline? Is this artifact attacker-created or a Windows default? It generates
   competing hypotheses and forces the Prosecutor to disprove them. **This catches the
   hallucinations.**
4. **Judge** rules each finding: ✅ **Confirmed** (survived), ⚠️ **Inference** (plausible, not
   proven), or ❌ **Inadmissible/speculation** (no evidence → flagged as a *caught*
   hallucination, not deleted — shown as a win).

## Two killer differentiators
- **Architectural guardrail, not a prompt:** the agent *physically cannot* modify evidence —
  the MCP server exposes no write/exec primitive, only typed read functions. SHA-256 the
  evidence image at start and end and prove it's unchanged. Strongest possible move for the
  **Constraint Implementation** criterion; test it for bypass and document the result.
- **Tamper-evident chain of custody:** every tool execution → an **append-only, hash-chained
  ledger** (each entry includes the prior entry's hash, a mini Merkle log). Every report line
  links to its ledger entry → tool call → raw output hash. A judge can trace any sentence to
  bytes on disk. This *is* the **Audit Trail** criterion done the way an FBI examiner dreams.

## Maps to all 6 judging criteria
| Criterion | How it's nailed |
|---|---|
| 1. Autonomous Execution (tiebreaker) | Prosecutor↔Defense loop drives next steps, handles tool failures, self-corrects live. |
| 2. IR Accuracy | Cross-examination catches hallucinations; verdict separates Confirmed / Inference / flagged speculation. |
| 3. Breadth & Depth | Go deep on disk image + memory capture correlation (depth beats breadth). |
| 4. Constraint Implementation | Read-only typed MCP server + evidence hashing + documented bypass test. |
| 5. Audit Trail | Hash-chained append-only ledger; every finding traces to a tool execution. |
| 6. Usability & Docs | Courtroom/case-file metaphor is intuitive; transparent reasoning doubles as analyst training. |

## UI/UX — the "Case Board"
A modern detective's case board (live web deployment URL is allowed alongside the terminal demo):
- **Investigation graph** — hypothesis cards linked to evidence exhibits with confidence meters;
  progressive disclosure (overview → drill into raw artifact + tool call).
- **Live reasoning stream** — Prosecutor vs Devil's Advocate debate side-by-side (the
  analyst-training feature: juniors watch a senior reason).
- **Verdict report** — color-coded Confirmed / Inference / Caught-hallucination; every line a
  clickable citation to the ledger.
- Design principles honored: visibility of system status, progressive disclosure, recognition
  over recall, consistency, error prevention, match to the real world, accessibility
  (icon+color, high contrast, keyboard nav, jargon tooltips).

## Stack & scope (solo)
- **Claude Code** as the agent framework (preferred track) + **custom Python MCP server**
  (highest-scoring architecture).
- **MVP:** read-only MCP server with ~6–8 typed tools, Prosecutor↔Advocate↔Judge loop,
  hash-chained ledger, run against provided sample disk+memory image.
- **Wow layer:** web Case Board, documented bypass test in the accuracy report.

## Risks
- Two LLMs arguing is still LLM-vs-LLM — both can be wrong. (Mitigation: add a deterministic
  verification tier; see Idea 01b / COUNSEL in the comparison doc.)
- Multi-agent loops can spiral — needs hard max-iteration caps + graceful degradation.

## Codex findings and refined idea

### Verdict
Build the **A+ COUNSEL** version: a falsification-first autonomous DFIR agent. The courtroom
metaphor is memorable, but the prize-worthy contribution is the claim-verification protocol,
not merely having multiple agents debate. Combine the strongest parts of the comparison
ideas into one cohesive system:

- **DEVIL'S ADVOCATE:** adversarial cross-examination and clear storytelling.
- **POLYGRAPH:** quantified benchmarking against known ground truth.
- **REWIND:** a source-corroborated attack timeline in the UI.
- **THE CAGE:** architectural read-only enforcement and documented bypass tests.

### Refined autonomous loop
1. The **Prosecutor** proposes a structured claim with a citation, confidence level, and the
   next investigative action.
2. The deterministic **Clerk** validates factual fields such as hashes, paths, offsets,
   timestamps, registry values, and counts. Important claims should use an independent tool
   or a second evidence source when available.
3. The **Devil's Advocate** searches for benign explanations, contradictory artifacts, and
   missing evidence using Analysis of Competing Hypotheses.
4. A bounded controller chooses the next tool call from unresolved contradictions, handles
   tool failures, and stops at a hard maximum iteration count.
5. The **Judge** labels each claim as **Confirmed**, **Inference**, **Contradicted**, or
   **Unresolved**. Rejected claims remain visible as caught errors.
6. Every ruling links back to the exact MCP call, raw output hash, and cited artifact.

### Technical corrections
- Re-running the same parser and byte-matching its output proves reproducibility, not truth.
  A parser bug can reproduce perfectly. Use independent corroboration for important claims.
- A hash-chained ledger is tamper-evident only when its final digest is signed or checkpointed
  somewhere the agent cannot rewrite. Store a signed final manifest or external checkpoint.
- A read-only MCP server protects evidence only if the agent cannot bypass it through shell
  access. Mount original evidence read-only, expose typed MCP tools, deny unrestricted shell
  execution in the investigation runtime, and include bypass attempts in the accuracy report.
- The demo must visibly show autonomous self-correction: a claim is challenged, additional
  evidence is collected, and the final ruling changes without human intervention.

### Focused solo scope
Do not wrap the entire SIFT toolset. Ship 6-8 reliable typed tools around one excellent
disk-and-memory case:

- timeline extraction
- file metadata and hashing
- registry persistence inspection
- Prefetch inspection
- Amcache or Shimcache inspection
- YARA scanning
- memory process listing
- network artifact extraction

Depth on fewer evidence types is better than shallow coverage. Benchmark confirmed findings,
false positives, missed artifacts, caught hallucinations, and evidence-integrity bypass tests.

### Case Board UI
Keep the frontend focused and educational:

- **Case Overview:** incident summary, investigation status, confidence distribution, and
  current autonomous action.
- **Attack Timeline:** corroborated disk, memory, and inferred events with clear filters.
- **Claim Court:** allegation, exhibits, counterarguments, ruling, and confidence.
- **Evidence Ledger:** expandable MCP calls, hashes, timestamps, token usage, and replay links.

Use progressive disclosure: plain-language "Why this matters" explanations for new analysts
and technical drill-downs for experienced responders. Include keyboard navigation, high
contrast, visible system status, and icons alongside color.

### Submission positioning
**COUNSEL: A Falsification-First Autonomous DFIR Agent**

The concise pitch: COUNSEL does not trust its first answer. It treats every finding as an
allegation, deterministically verifies factual claims, searches for evidence that would
disprove its own reasoning, and publishes only rulings that remain traceable to the original
artifacts and tool executions.
