# Idea 02 - COUNSEL (the 10/10 version)

> **COUNSEL - A Corroboration-First Autonomous DFIR Agent.**
> It never asserts its first answer. Every finding is weighed against independent evidence
> across sources and reported with a precise claim state - never as a bare "confirmed" or
> "falsified".

This is the final, gap-proofed evolution of [Devil's Advocate](01-devils-advocate.md). It keeps
the memorable courtroom *vocabulary* but moves the real novelty out of "two AIs arguing" (an
over-used pattern) and into a **cross-source corroboration engine** with disciplined evidentiary
reasoning - the part competitors do poorly and the part that wins the criteria you are
structurally weakest on.

NOTE: This document is intentionally ASCII-only (no box-drawing, smart-quotes, or arrow glyphs)
so it stays clean in a public GitHub repo on any platform.

---

## The one novel idea that makes this win
**The Corroboration Engine.** A single artifact rarely proves anything; a senior analyst trusts
a finding only when *independent* sources of differing evidentiary weight agree. Protocol SIFT
hallucinates because the LLM trusts a single tool's output and narrates it confidently.

COUNSEL encodes investigative tradecraft as **declarative corroboration rules**. Each rule does
NOT ask "is this true/false". It asks: which independent artifacts *support* this specific claim,
which would *contradict* it, how *reliable and independent* is each signal, and therefore what
**claim state** is defensible.

This converts expert knowledge into **data**, so accuracy no longer depends on *your* DFIR
intuition (your weak spot as a strong-dev-new-to-DFIR). It is also a reusable community artifact -
the "lives on as a tool" outcome the brief prizes. **This is the contribution, not the courtroom
theme.**

---

## Claim states (the disciplined vocabulary)
Replaces the naive Confirmed/Falsified framing. Every claim resolves to exactly one state:

- **Observed** - directly present in one artifact (e.g. a Run-key value exists).
- **Corroborated** - supported by independent evidence of sufficient weight.
- **Inference** - a plausible interpretation with incomplete support.
- **Contradicted** - genuinely conflicting evidence exists.
- **Unresolved** - insufficient evidence after bounded investigation.

Critical rule: **absence of evidence is `Unresolved` / not-corroborated, NOT `Contradicted`.**
Artifacts can be absent, disabled, or cleared. Only *actively conflicting* evidence yields
`Contradicted`.

## Claims are decomposed, not lumped
A single "malicious persistence" claim hides three independent facts. COUNSEL separates them so
each carries its own evidence and state:

- **persistence_configured** - a persistence mechanism (e.g. Run key) is set to launch a payload.
- **payload_executed** - that payload actually ran at some point in the past.
- **payload_active** - that payload is resident/running now.

A missing binary does NOT contradict `persistence_configured` - it may mean deleted malware, a
broken/inactive remnant, or anti-forensics. It simply lowers support for `payload_active`.

## Confidence: weighted by reliability and independence (never a raw count)
Sources are NOT equal, and two artifacts derived from the same underlying source are NOT
independent. Rough evidentiary weights (per claim type - this is the encoded tradecraft):

| Artifact | persistence_configured | payload_executed | payload_active | Notes |
|---|---|---|---|---|
| Registry Run key | strong | none | none | proves configuration, not execution |
| Prefetch | none | strong | none | run count + timestamps; only if enabled |
| Amcache | weak/medium | medium | none | presence/first-seen; execution is debated, treat as supporting not proof |
| ShimCache (AppCompatCache) | none | weak | none | presence, NOT proof of execution |
| Binary on disk + hash | supporting | supporting | supporting | existence only; absence != contradiction |
| Memory (pslist/netscan) | none | none | strong | the only strong signal for "active now" |

Confidence = a weighted blend of the supporting signals' reliability *and their mutual
independence*, minus the weight of any contradicting signals. Two strong *independent* signals
beat five weak or co-dependent ones.

## Signature is a modifier, not a falsifier
A Microsoft (or otherwise valid) signature does **not** clear a payload - attackers abuse signed
binaries (LOLBins, signed-binary proxy execution, masquerading). Treat signing status as a
**confidence modifier / benign indicator**, weighed against path anomalies, masquerading, and
the persistence context. Never let a signature alone resolve a claim to benign.

---

## Worked example rule: `persistence_via_run_key`
```
claim graph emitted:
  persistence_configured   <- Run-key value present [registry]            => Observed
  payload_present_on_disk   <- referenced binary exists + hashed [fs]      => Observed | Unresolved
  payload_executed          <- Prefetch run record [prefetch]              (strong)
                               + Amcache entry [amcache]                   (medium, independent)
  payload_active            <- process in memory / netscan [memory]        (strong)

modifiers:
  signature_status [authenticode] -> lowers/raises suspicion, never resolves benign
  path/masquerade anomaly         -> raises suspicion

resolution:
  persistence_configured = Observed (registry value is direct)
  payload_executed       = Corroborated   if Prefetch AND Amcache agree (independent)
                         = Inference       if only one weak source
                         = Unresolved      if no execution artifacts found (NOT Contradicted)
                         = Contradicted    only if an artifact actively conflicts
  payload_active         = Corroborated    if live process; else Unresolved
```

---

## How COUNSEL counters every gap from the negative review
| Gap | How it is closed |
|---|---|
| "Debate/critic is over-used" | Novelty is the **weighted corroboration rule engine**, not agents arguing. One LLM. |
| "Read-only MCP & hashing = everyone has it" | Table stakes; wow-budget goes to corroboration + a **documented bypass test** few will run. |
| "Weak on IR Accuracy (your gap)" | Tradecraft encoded as weighted rules + a **ground-truth benchmark case** define correctness, not your judgment. |
| "Re-running same parser != truth" | Verification uses **independent corroboration** across different artifacts/sources. |
| "Ledger tamper-evidence" | **Signing key lives outside the agent runtime** (trusted launcher / separate verifier signs the final manifest). |
| "Read-only MCP bypassable via shell" | Investigation runtime is **MCP-only, no shell**; evidence mounted read-only; bypass attempts documented. |
| "Glossy web UI reads as fluff to DFIR judges" | **Terminal-first**: rich TUI + auto-generated static HTML "Case File" (no server). |
| "Multi-agent cost/spiral" | Single-agent loop; self-correction driven by corroboration gaps; hard max-iteration cap. |
| "13 days, solo" | Start at **4 tools, 5 rules**; expand only after the end-to-end loop works. |

---

## Trust boundaries (state these precisely in the architecture diagram)
**Ledger trust boundary.** The agent may *append* structured entries to the hash-chained ledger
during investigation, but it **cannot sign**. The signing key never enters the agent runtime. A
**trusted launcher** starts the run and a **separate verifier process** holds the key and signs
the final manifest (the chain head + run metadata) after the agent exits. Tamper-evidence comes
from that externally-held signature, not from the chain alone.

**Claude Code / Protocol SIFT boundary.** Claude Code remains the **primary execution engine**
(as Rules.md requires). During investigation, however, the agent is granted **MCP-only
capabilities**: the read-only typed tools are its sole path to evidence, and the runtime exposes
**no shell / no exec primitive**, so it physically cannot bypass the MCP layer to touch raw
evidence. This satisfies Rules.md line 490 ("Projects must run on or integrate with the SANS SIFT
Workstation using Claude Code or OpenClaw as the agentic framework") while enforcing the
read-only guarantee architecturally rather than by prompt.

## Architecture (single-agent, terminal-first)
```
  +------------------------------------------------------------+
  |  EVIDENCE  (mounted READ-ONLY: disk image + memory slice)  |
  +------------------------------------------------------------+
              ^  read-only, no shell path to raw evidence
  +------------------------------------------------------------+
  |  READ-ONLY MCP SERVER  - typed tools, structured output     |
  |  registry . prefetch . amcache . hash/metadata              |
  |  (expand) timeline . yara . mem pslist/netscan              |
  |  every call -> append to hash-chained ledger                |
  +------------------------------------------------------------+
              ^ structured findings           |  append-only (cannot sign)
  +-------------------------------------------+----------------+
  |  AGENT LOOP (Claude Code, MCP-only, no shell)              |
  |  1 propose claim {type, citation, support, state}          |
  |  2 CORROBORATION ENGINE: weight signals, set claim state   |
  |  3 on gap/contradiction -> autonomously gather more        |  <- SELF-CORRECTION
  |  4 resolve state: Observed/Corroborated/Inference/         |
  |     Contradicted/Unresolved   (rejected claims stay shown) |
  |  hard max-iteration cap + graceful degradation            |
  +------------------------------------------------------------+
              v
  +------------------------------------------------------------+
  |  TRUSTED LAUNCHER / VERIFIER (key OUTSIDE agent) signs the  |
  |  final manifest -> tamper-evident ledger                    |
  +------------------------------------------------------------+
              v
  OUTPUT: TUI report + static HTML "Case File" + signed ledger
  (every ruling -> MCP call -> raw output hash -> artifact offset)
  + benchmark / accuracy report
```

## 10/10 mapping
| Criterion | Why it is a 10 |
|---|---|
| 1. Autonomous Execution (tiebreaker) | Corroboration-gap-driven loop chooses next tool, handles failures, self-corrects on camera, bounded. |
| 2. IR Accuracy | Weighted independent corroboration + calibrated claim states + ground-truth benchmark + visibly caught hallucinations. |
| 3. Breadth & Depth | Deep on one case; cross-source (disk + memory) corroboration is the depth story. |
| 4. Constraint Implementation | Read-only mount + MCP-only/no-shell runtime + externally-signed ledger + documented bypass test. |
| 5. Audit Trail | Signed hash-chained ledger; every ruling -> exact MCP call -> raw output hash -> artifact offset. |
| 6. Usability & Docs | Terminal report clarity, "why this matters" for juniors, reproducible benchmark, extensible rules. |

## The UI/UX, done right for this audience
- **Hero:** a polished rich-terminal TUI (status, current autonomous action, claim-state distribution).
- **Deliverable artifact:** an auto-generated **static HTML "Case File"** from the ledger - offline,
  no server. Sections: Case Overview . Attack Timeline (disk+memory corroborated) . Claim Court
  (claim -> supporting/contradicting exhibits -> weighted state) . Evidence Ledger (expandable MCP
  calls, hashes, token usage, replay links).
- Progressive disclosure: plain-language "Why this matters" for juniors, technical drill-down for
  pros. Icon+text labels (not color-only), high contrast, keyboard nav, jargon tooltips.

---

## Minimum winning demo (build to exactly this first)
1. Agent observes a suspicious Run key -> `persistence_configured = Observed`.
2. COUNSEL marks the linked `payload_executed` as `Inference` (only weak/single support so far).
3. Rule engine flags the gap: no independent execution evidence yet.
4. Agent autonomously checks Prefetch and Amcache.
5. Independent agreement raises `payload_executed` to `Corroborated` - the ruling changes on camera.
6. HTML "Case File" links that ruling to its ledger entries and artifact offsets.
7. A bypass test demonstrates an attempted evidence modification FAILS (architectural, not prompt).

## 13-day solo plan (today = 2026-06-02 . deadline 2026-06-15 23:45 EDT)
**Risk note:** SIFT OVA + Protocol SIFT setup and choosing a ground-truth case can eat days - do
this first and timebox hard.

| Days | Goal |
|---|---|
| 1-2 | Stand up SIFT + Protocol SIFT. Pick ONE ground-truth case (image with a published answer key) + the provided compromised-system data. Skeleton: read-only MCP server + Claude Code (MCP-only, no shell) + empty ledger + trusted launcher stub. |
| 3-5 | Build **4 typed read-only MCP tools** with structured output + ledger append: registry, prefetch, amcache, hash/metadata. Verify each by hand against the case. |
| 6-8 | **Corroboration Engine + 5 rules** (the persistence_configured / payload_present / payload_executed / execution_corroboration / signature_modifier set). Weighted scoring + claim-state resolution. Wire the agent loop with hard max-iteration cap. |
| 9-10 | Make a ruling visibly change via self-correction (steps 1-5 above). External signing of the manifest. Run the **evidence-integrity bypass test**. |
| 11-12 | Benchmark vs baseline; **accuracy report** (observed/corroborated/inference/contradicted/unresolved counts, false positives, missed artifacts, caught hallucinations, bypass results). Generate TUI + HTML Case File. Architecture diagram (with trust boundaries). README + docs. |
| 13 | Record the 5-min narrated terminal demo (must show one self-correction). Submit on Devpost. Buffer. |

## Scope discipline (expand only after the loop works end-to-end)
- Add tools in this order after the 4-tool MVP: timeline, yara, memory pslist/netscan.
- Memory unlocks `payload_active` and the strongest cross-source corroboration - add it second.
- **Never cut:** read-only/no-shell enforcement, the externally-signed ledger, the benchmark, or
  the on-camera self-correction. Those four are the score.

## Submission positioning (Devpost story)
**COUNSEL: A Corroboration-First Autonomous DFIR Agent.** COUNSEL does not assert its first
answer. It treats every finding as a claim with a precise evidentiary state, weighs independent
corroboration across evidence sources before raising confidence, autonomously hunts the evidence
that would change its own ruling, and publishes only results that trace back - through an
externally-signed ledger - to the original artifacts and the exact tool executions that produced
them.
