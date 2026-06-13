# COUNSEL - Written Description (Devpost Submission)

## What I Built

COUNSEL (Corroboration-First Autonomous DFIR Agent) is an autonomous digital forensics agent
that refuses to assert a finding as confirmed until two or more independent forensic artifact
families agree - mathematically, not by LLM confidence. It runs on SIFT Workstation, wraps
10 real forensic tools (Volatility, YARA, tshark, Zimmerman tools, python-evtx) as a
custom MCP server (Pattern 2 - the architecture the hackathon judges rated "most sound"),
and produces a hash-chained, Ed25519-signed audit ledger after every investigation.

**Relationship to Protocol SIFT:** COUNSEL extends the hackathon's own Protocol SIFT framework.
Where Protocol SIFT demonstrates how Claude agents CAN interface with SIFT forensic tools via MCP,
COUNSEL answers the harder question: how do you stop the agent from hallucinating findings?
The corroboration engine, 5-state claim model, and declarative rule DSL are built on top of
the MCP tool-use pattern that Protocol SIFT defines - not as a competing approach but as a
principled constraint layer above it.

## One-Sentence Summary
COUNSEL is a corroboration-first autonomous DFIR agent that never asserts a finding as confirmed unless two independent forensic sources agree, every decision is hash-chain auditable, and the evidence image is cryptographically verified to be unmodified.

## The Problem

The SANS FIND EVIL! hackathon was created because Protocol SIFT - and AI-powered DFIR tools generally - **hallucinate more than we'd like**. The same adversaries who reach domain control in under 8 minutes (GTG-1002, CrowdStrike 7-minute breakout) are increasingly using AI to automate attacks. Defenders need an AI partner they can trust at 3 AM during an active incident - one that shows its work and refuses to overclaim.

The core problem with existing AI DFIR approaches is **epistemic**: the LLM asserts findings with unwarranted confidence. One registry key observation becomes a CORROBORATED persistence finding. One network connection becomes a C2 channel. These assertions propagate into incident reports and can result in wrong remediation actions.

## The Solution: Corroboration-First

COUNSEL treats every forensic finding as a claim that starts at OBSERVED and can only reach CORROBORATED when **two or more independent artifact families agree**. This mirrors how senior forensic examiners actually think: "Prefetch says it ran, Amcache says it ran - those are independent Windows subsystems, so execution is confirmed." One source is never enough.

### The 5-State Epistemic Model

Every claim in COUNSEL has exactly one of five states:
- **OBSERVED**: Single artifact. Investigation begins here.
- **INFERENCE**: Some evidence, below corroboration threshold.
- **CORROBORATED**: Two+ independent sources agree (support >= 0.80).
- **CONTRADICTED**: Evidence actively conflicts.
- **UNRESOLVED**: Bounded search exhausted honestly.

The corroboration engine - not the LLM - computes state using a noisy-OR model over independence groups. The agent reads states but cannot assert CORROBORATED unilaterally.

## Architecture: Three Trust Boundaries

COUNSEL uses four OS processes with distinct privilege:

1. **Trusted Launcher**: Holds the Ed25519 signing key, mounts evidence read-only, spawns MCP server, calls Verifier after agent exit.
2. **MCP Server**: Exposes 11 typed forensic tool functions (no shell, parse-before-return). Appends to the ledger.
3. **Agent Runtime (Claude Haiku 4.5)**: MCP-only tools, no shell, no write mount, cannot sign.
4. **External Verifier**: Recomputes hash chain, verifies evidence SHA256 (hash_in == hash_out), signs manifest with Ed25519.

Three trust boundaries are enforced architecturally (not via prompts):
- **B1**: Agent reaches evidence ONLY through typed MCP functions
- **B2**: Signing key lives outside the agent's process
- **B3**: Agent has no shell, no exec, no write mount

## Genuinely Novel Contributions

**1. Declarative Corroboration Rule DSL**
A YAML mini-language for expressing DFIR corroboration knowledge. Each rule cites its forensic provenance (SANS course, Zimmerman tool documentation, MITRE ATT&CK), defines signals with independence groups, and fails closed at load time if malformed. This is community-extensible - any DFIR practitioner can write a new rule without touching Python.

**2. Formal Claim-State Epistemics**
The combination of the 5-state model, noisy-OR confidence with independence-group partitioning, and Expected Calibration Error measurement makes COUNSEL's confidence scores empirically meaningful. When the agent says "CORROBORATED at 0.95," the calibration report shows what fraction of 0.90–1.00 claims were actually correct against the ground-truth answer key.

**3. Prompt-Injection-Resistant Evidence Handling**
Adversarial content in evidence (maliciously named files, registry values containing LLM instruction overrides) is addressed at two levels: (a) parse-before-return strips control characters and bounds string length before the LLM sees it; (b) the agent has no exec/write primitive, so even a successful injection has nothing dangerous to call. This directly addresses the weaponized-AI threat (GTG-1002) the hackathon was created around.

## What 10/10 on Every Criterion Looks Like

- **Autonomous Execution**: Agent forms hypotheses, hits dead ends, recovers from tool failures, and produces multiple genuine ruling changes driven by gap detection (not scripting).
- **IR Accuracy**: Benchmarked against locked ground-truth answer key. Published precision, recall, FPR, hallucination rate, and calibration curve. "Hallucinations We Caught" gallery included - radical honesty as a feature.
- **Breadth/Depth**: Full kill chain across disk + memory + network. MITRE ATT&CK mapped. Super-timeline. Benchmarked against a locked answer key (see Accuracy Report); architecture is case-agnostic and designed to extend to additional fixtures via `COUNSEL_FIXTURE_DIR`.
- **Constraint Implementation**: Published threat model. RT1–RT7 red-team tests documented failing safely. Prompt injection planted inside evidence (RT3) - the architecture holds because the agent has no dangerous primitives.
- **Audit Trail**: Every finding → ledger entry → tool call → raw output SHA256 → artifact path + offset. `counsel replay` re-runs any finding on demand. Exportable signed case package.
- **Usability**: One-command setup. Terminal-first (SIFT-native Rich TUI). Static HTML Case File (no web server). Analyst Training Mode. Community DSL with 5-minute onboarding guide.

## How I Built It

COUNSEL took 3 weeks of solo development:

1. **Corroboration engine** (`counsel/engine/`) - noisy-OR confidence math with independence
   group partitioning. Fail-closed on malformed rules. All state transitions logged.

2. **Custom MCP server** (`counsel/mcp_server/`) - 11 typed forensic tools, parse-before-return
   (control chars stripped, strings bounded to 512 chars), read-only evidence access,
   hash-chained ledger append. Never exposes raw tool output to the LLM.

3. **Declarative rule DSL** (`counsel/rules/`) - YAML corroboration rules that cite
   forensic provenance (SANS course, Zimmerman docs, ATT&CK). Community-extensible.

4. **Claude Haiku 4.5 agent loop** (`counsel/agent/`) - adaptive thinking, MCP-only tools,
   no shell, no write access.

5. **Fixture system** (`counsel/fixtures/`) - pre-recorded Szechuan Sauce tool outputs.
   Full investigation demo without SIFT Workstation. Set COUNSEL_FIXTURE_DIR and run.

6. **FastAPI dashboard** (`counsel serve`) - live claims board, SSE agent stream, audit
   ledger viewer, ATT&CK Navigator layer export.

## Challenges

The hardest problem was the independence group definition. Early versions let the agent
call the same tool twice on different parameters and count both calls as independent
signal - which let it CORROBORATE a claim from a single artifact family. The fix was
partitioning signals by `independent_of` field and taking max weight per partition,
not sum. This is the core anti-hallucination mechanism and took 3 iterations to get right.

The second hard problem was prompt injection resistance. Adversarial content in evidence
(filenames designed to override LLM instructions) would pass through raw tool output and
reach the agent context. Parse-before-return addresses this at the MCP layer - not by
filtering LLM output but by never letting raw evidence bytes reach the LLM.

## What I Learned

The key insight: you cannot make an LLM agent trustworthy by prompting it to be careful.
Trust comes from architectural constraints. The agent cannot overclaim because the
corroboration engine controls state. It cannot exfiltrate evidence because it has no
write primitive. It cannot tamper with the audit trail because it cannot sign. These
properties are enforced by process isolation, not by prompts.

## What's Next

- Community corroboration rule registry (like YARA rules but for DFIR logic)
- Calibration-aware confidence reporting (ECE metric per rule, not just per case)
- Expansion to Linux artifacts (ext4 MFT equivalent, bash history, auditd logs)

## Demo Narrative (5 minutes)

The demo follows 9 beats: evidence mount + start → triage at speed → Run key → honest INFERENCE → self-correction live (Amcache corroborates Prefetch → CORROBORATED) → cross-source (memory + PCAP) → hallucination caught → constraint test (RT3 fails safely) → replay + signed case file. The self-correction moment is the climax: a claim changes from INFERENCE to CORROBORATED on camera, driven by the engine.
