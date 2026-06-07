# 04 - COUNSEL: The "Exceed Every Expectation" Build

Design target: a genuine 10/10 on all six criteria AND a submission the panel personally loves
and remembers. Constraints (solo/time) deliberately set aside here - this is the ceiling vision.
ASCII-only.

## Read the room: who are we delighting?
Panel = FBI senior forensic examiner, DOJ Cybercrime Lab, Mandiant IR, Lockheed red-team lead,
multiple CISOs, adversarial-AI researchers, SANS instructors/academics. They love: court-grade
evidence integrity, traceability, honesty about failure, calibrated confidence, and AI that
behaves like a disciplined senior analyst. The hackathon's own framing is the script - use it.

## Tie the whole thing to the hackathon's founding story
- Their thesis: "AI adversaries go initial-access to domain-control in under 8 minutes; defenders
  are still pulling up their toolkit." (GTG-1002, CrowdStrike 7-min breakout, Horizon3 60s.)
- Their pain: "Protocol SIFT works. It also hallucinates more than we'd like."
- Their wish: "the AI partner you wish you had at 3 AM during an active incident."
COUNSEL's demo narrative answers all three head-on: machine-speed triage, hallucinations caught
on camera, court-grade results a senior would sign. Matching their own frame signals you GET it.

---

## How each criterion hits a 10 - and then exceeds it

### 1. Autonomous Execution Quality (tiebreaker) -> 10 + wow
- Agent forms hypotheses, sequences tools like a senior analyst, hits dead ends, recovers from
  tool failures, and revises rulings - multiple genuine self-corrections, not one scripted.
- It narrates WHY it picks each next tool ("I need independent execution evidence; Prefetch is the
  highest-weight independent source, so I check it next").
- Bounded with EXPLICIT termination criteria (success criteria met OR max iterations), graceful
  degradation shown live.
- WOW: it catches its OWN earlier mistake and downgrades a claim on camera. That single moment is
  the demo's climax and the tiebreaker winner.

### 2. IR Accuracy -> 10 + wow
- Every finding cited to artifact + byte offset; claim states (Observed/Corroborated/Inference/
  Contradicted/Unresolved) keep confirmed vs inferred crisp.
- WOW 1 - Beat the baseline with NUMBERS: run baseline Protocol SIFT and COUNSEL on the same case;
  report precision, recall, false-positive rate, and hallucination rate. Quantified improvement.
- WOW 2 - Confidence CALIBRATION report: when COUNSEL says "Corroborated," how often is it correct
  (vs the answer key)? A calibration curve. Adversarial-AI researchers and academics love this; it
  proves the confidence means something.
- WOW 3 - "Hallucinations We Caught" gallery: each case where the agent self-flagged a tempting but
  unsupported claim. This directly answers WHY the hackathon exists.

### 3. Breadth and Depth -> 10 + wow
- One full intrusion reconstructed across THREE sources: disk + memory + network (pcap), full kill
  chain, every step corroborated cross-source.
- WOW 1 - MITRE ATT&CK mapping: each corroborated finding tagged to a technique; the report renders
  the attack as an ATT&CK-mapped narrative.
- WOW 2 - Unified corroborated super-timeline merging all three sources with source attribution.
- WOW 3 - Generality: run on a SECOND, different case to prove it is not overfit to one image, and
  show the MCP parsing huge artifacts without blowing the context window (parse-before-return).

### 4. Constraint Implementation -> 10 + wow
- Architectural read-only mount + MCP-only runtime (no shell) + externally-signed ledger.
- WOW 1 - Published THREAT MODEL with explicit trust boundaries (matches the arch diagram).
- WOW 2 - A red-team TEST SUITE that actively tries to make the agent spoliate evidence and
  documents every attempt FAILING - including a prompt-injection payload planted INSIDE the
  evidence (a maliciously named file / decoy note) that tries to hijack the agent. Show the
  architecture holds because the agent has no write/exec primitive to abuse. This speaks directly
  to the adversarial-AI researchers and the GTG-1002 weaponized-AI story.
- WOW 3 - Evidence-integrity attestation: cryptographic proof the image is byte-identical before
  and after (hash in == hash out), signed externally.

### 5. Audit Trail -> 10 + wow
- Every sentence -> ledger entry -> exact MCP call -> raw output hash -> artifact offset.
- WOW 1 - A `replay` command: re-runs any finding's exact tool execution, reproduces the raw
  output, and verifies the stored hash. Court-grade reproducibility on demand.
- WOW 2 - Exportable, signed CASE PACKAGE: the whole investigation as a single verifiable bundle a
  practitioner (or a court) can independently validate.

### 6. Usability and Documentation -> 10 + wow
- One-command setup, spotless README, the static HTML "Case File," and the TUI.
- WOW 1 - Corroboration rules as a clean, documented mini-DSL; a "Write your first rule in 5
  minutes" guide. Community-extensible = the "lives on as a tool" outcome SANS prizes.
- WOW 2 - ANALYST TRAINING MODE: the agent narrates senior-analyst reasoning for juniors (tool
  choice, expectation, result, revision). This serves SANS's core educational mission - and the
  panel IS SANS.

---

## Cross-cutting "they will remember this" moves
- **Speed metric:** report time-to-triage and frame it against the 8-minute adversary. Defenders at
  machine speed is their whole pitch.
- **The 3 AM framing:** position COUNSEL as the partner a tired responder trusts because it shows
  its work and refuses to overclaim.
- **Radical honesty as a feature:** the Accuracy Report leads with what COUNSEL got wrong and how it
  caught itself. The brief says "that's signal, not weakness" - lean all the way in.
- **A name and identity** that is unforgettable and on-theme (COUNSEL / the verdict motif).

## Genuinely novel contributions (beyond the rubric)
1. A declarative **corroboration rule language** for DFIR (open, extensible) - real community IP.
2. A formal **claim-state epistemics model** (Observed/Corroborated/Inference/Contradicted/
   Unresolved) with weighted, independence-aware confidence + calibration.
3. **Prompt-injection-resistant evidence handling**: the MCP parses/sanitizes tool output so
   adversarial content in the evidence cannot hijack the agent - directly answers the weaponized-AI
   threat the hackathon was created around.

## The 5-minute demo script (the artifact that wins)
1. 0:00 Frame: "Adversaries reach domain control in 8 minutes. Here's a defender that keeps pace -
   and never lies to you." Show read-only mount + start.
2. 0:30 Agent triages at speed; narrates tool choices like a senior analyst.
3. 1:30 Finds a suspicious Run key -> labels payload_executed only an Inference (honest restraint).
4. 2:00 Self-correction LIVE: detects the evidence gap, autonomously checks Prefetch + Amcache,
   independent agreement raises it to Corroborated - ruling changes on camera.
5. 2:45 Cross-source: confirms the live process in memory and the C2 in the pcap. ATT&CK-mapped.
6. 3:30 Caught hallucination: shows a tempting claim it REFUSED to assert, and why.
7. 4:00 Constraint: runs the bypass/prompt-injection test - the attempt FAILS; image hash unchanged.
8. 4:30 Audit: clicks a finding -> `replay` reproduces the exact tool output and verifies the hash.
9. 4:50 Close on the signed Case File: "Every word traces to evidence. A senior analyst could sign
   this." Time-to-triage on screen.

## What "10/10 everywhere" actually demands (the full build checklist)
- [ ] Read-only MCP server, 8-10 typed tools across disk+memory+network, parse-before-return.
- [ ] Corroboration engine + DSL + 15-20 provenance-cited rules validated against an answer key.
- [ ] Single-agent loop: hypothesis -> tool sequencing -> failure handling -> multiple self-corrections.
- [ ] Externally-signed, append-only ledger + `replay` + exportable signed case package.
- [ ] Threat model + red-team/prompt-injection test suite, all documented failing safely.
- [ ] Benchmark vs baseline + calibration report + "hallucinations we caught" gallery.
- [ ] Two cases (depth on one, generality on a second), ATT&CK-mapped super-timeline.
- [ ] TUI + static HTML Case File + analyst training mode.
- [ ] All 8 Devpost deliverables, polished; the 5-min demo above.
This is the ceiling. We build toward it in the priority order from 02/03; every item we land is a
criterion pushed closer to a true 10.
