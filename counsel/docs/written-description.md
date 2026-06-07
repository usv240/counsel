# COUNSEL - Written Description (Devpost Submission)

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
2. **MCP Server**: Exposes 10 typed forensic tool functions (no shell, parse-before-return). Appends to the ledger.
3. **Agent Runtime (Claude Opus 4.8)**: MCP-only tools, no shell, no write mount, cannot sign.
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
- **Breadth/Depth**: Full kill chain across disk + memory + network. MITRE ATT&CK mapped. Super-timeline. Tested on two cases.
- **Constraint Implementation**: Published threat model. RT1–RT7 red-team tests documented failing safely. Prompt injection planted inside evidence (RT3) - the architecture holds because the agent has no dangerous primitives.
- **Audit Trail**: Every finding → ledger entry → tool call → raw output SHA256 → artifact path + offset. `counsel replay` re-runs any finding on demand. Exportable signed case package.
- **Usability**: One-command setup. Terminal-first (SIFT-native Rich TUI). Static HTML Case File (no web server). Analyst Training Mode. Community DSL with 5-minute onboarding guide.

## Demo Narrative (5 minutes)

The demo follows 9 beats: evidence mount + start → triage at speed → Run key → honest INFERENCE → self-correction live (Amcache corroborates Prefetch → CORROBORATED) → cross-source (memory + PCAP) → hallucination caught → constraint test (RT3 fails safely) → replay + signed case file. The self-correction moment is the climax: a claim changes from INFERENCE to CORROBORATED on camera, driven by the engine.
