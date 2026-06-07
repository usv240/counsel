# FIND EVIL! — Strategy & Idea Comparison

**Profile:** solo, strong dev, new to DFIR. Deadline Jun 15, 2026. Prize $22K (SANS).

## Hard requirements (fail any = elimination / Stage-One fail)
- Must be an **autonomous IR agent** using an agentic framework (Claude Code / OpenClaw) as
  the *primary execution engine*. A pure tool/benchmark with no agent = Stage-One fail.
- Must demonstrate: **self-correction**, **accuracy validation** (findings traceable to
  artifacts/offsets/log entries), **analytical reasoning** (narrative, not raw log).
- Must run on Linux / SIFT Workstation. Public repo, MIT/Apache-2.0, README, video, arch
  diagram, dataset docs, accuracy report, execution logs. (8 components, all required.)

## What the judge panel signals
FBI examiner, DOJ Cybercrime Lab, Mandiant, Lockheed red team, multiple CISOs. They reward:
- **Architectural** guardrails over prompt guardrails (Criterion 4).
- **Chain of custody / traceability** — trace any finding to the exact tool execution (Crit 5).
- Honesty about failure modes (the brief says "that's signal, not weakness").
- Numbers that prove accuracy beats the baseline.

## Candidates

### A. DEVIL'S ADVOCATE — adversarial "courtroom" agent (see 01-devils-advocate.md)
Two LLM agents (Prosecutor builds case, Devil's Advocate cross-examines via ACH), Judge
renders verdict. Read-only MCP + hash-chained ledger.

### A+. COUNSEL — Devil's Advocate + a DETERMINISTIC verification tier (RECOMMENDED)
Same courtroom framing, but self-correction is **two-tier**:
- **Tier 1 — the Clerk (deterministic):** every *factual* claim (hash, path, offset,
  timestamp, registry value, count) is auto-re-verified by re-running the read-only MCP tool
  and byte-matching the raw artifact. Unverifiable claim → auto-flagged. (An LLM critic can
  itself hallucinate; deterministic re-execution cannot. Forensics judges trust this more.)
- **Tier 2 — the Devil's Advocate (LLM):** challenges the *reasoning/narrative* where
  determinism can't help — competing hypotheses, alternative benign explanations (ACH).
- **Benchmark layer:** run against ground-truth datasets (CTF images with answer keys) and
  publish numbers: accuracy, false-positive rate, hallucination rate **vs baseline Protocol
  SIFT**. This makes the required Accuracy Report a quantified, first-class result — and
  absorbs the entire value of Candidate B without its Stage-One risk.

### B. POLYGRAPH — benchmark-first accuracy harness
The star is a measurement harness + leaderboard scoring Protocol SIFT on ground-truth data.
High community value; leverages eval/CI strengths; ground-truth answer keys cover the
DFIR-knowledge gap. **Risk:** it's a *measurement* tool, not an autonomous agent → Stage-One
viability risk + weak on Criterion 1. Best used as a *layer inside A+*, not the whole project.

### C. REWIND — attack-reconstruction / super-timeline agent
Disk + memory → reconstructs the kill chain as a validated, source-corroborated timeline.
Self-correction = resolving contradictions between sources. Great Breadth/Depth + storytelling
UI. **Risk:** self-correction is subtler to demo; less of a distinct "wow" than the courtroom.

### D. THE CAGE — constraint-implementation-first
Whole pitch = a bulletproof read-only architecture + a documented red-team bypass test suite.
Wins Criterion 4 hard. **Risk:** thin on the other five criteria; narrow.

## Scorecard (1–5 per criterion; Feas = solo feasibility, S1 = Stage-One safety)
| Idea | C1 Auton | C2 Accuracy | C3 Depth | C4 Constraint | C5 Audit | C6 Usability | Feas | S1 | Total |
|---|---|---|---|---|---|---|---|---|---|
| A  Devil's Advocate | 5 | 4 | 4 | 5 | 5 | 5 | 4 | 5 | 37 |
| **A+ COUNSEL** | **5** | **5** | **4** | **5** | **5** | **5** | **4** | **5** | **38** |
| B  Polygraph | 2 | 5 | 3 | 3 | 5 | 4 | 5 | 2 | 29 |
| C  Rewind | 4 | 4 | 5 | 4 | 4 | 5 | 3 | 4 | 33 |
| D  The Cage | 3 | 3 | 2 | 5 | 4 | 3 | 5 | 4 | 29 |

## Recommendation
**A+ COUNSEL** — Devil's Advocate courtroom framing, upgraded with a deterministic
verification tier and a quantified benchmark. It is the only candidate that scores ≥4 on all
six criteria *and* is Stage-One-safe *and* feasible solo. It absorbs the strengths of B
(numbers), C (timeline depth via the Prosecutor), and D (architectural guardrail) without
their individual weaknesses.

### Why COUNSEL beats plain Devil's Advocate
The deterministic Clerk tier closes the one real hole — "two LLMs arguing can both be wrong."
For an audience of forensic examiners, *deterministic ground-truth re-execution* is the
credibility unlock. It turns IR Accuracy from a claim into a measured guarantee.
