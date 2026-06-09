# COUNSEL - Corroboration-First Autonomous DFIR Agent

> "Every word traces to evidence. A senior analyst could sign this."

COUNSEL is an autonomous incident-response agent built on one principle: **earn every verdict**.
A finding is only CORROBORATED when two independent forensic sources agree.
One confident tool result is OBSERVED. Two independent sources reaching the same conclusion is CORROBORATED.
The distinction matters in federal court.

Built for the **SANS FIND EVIL! 2026 Hackathon** ($22K prizes, June 2026).

---

## What Makes COUNSEL Different

| Feature | Protocol SIFT (baseline) | COUNSEL |
|---|---|---|
| Confidence model | LLM asserts confidence | Noisy-OR over independent evidence groups |
| Hallucination risk | High (one-shot assertions) | Low (must have 2+ independent sources) |
| Audit trail | Agent output only | Hash-chained ledger, tool call → raw output SHA256 |
| Evidence integrity | None | Ed25519 signed manifest, hash_in == hash_out |
| Self-correction | Prompted | Emerges from gap detection engine |
| Constraint implementation | Prompt-level | Architectural (read-only mount, typed MCP, no shell) |
| Prompt injection defense | None | Parse-before-return + capability isolation |
| Community extensibility | None | Declarative YAML corroboration DSL |

---

## Quick Start (SIFT Workstation)

```bash
# Install
git clone https://github.com/usv240/counsel
cd counsel
pip install -e .

# Configure
export ANTHROPIC_API_KEY=sk-ant-...

# Mount evidence read-only (critical for integrity)
sudo mount -o ro,loop /path/to/evidence.E01 /mnt/evidence

# Generate signing key (one-time)
counsel keygen ~/.counsel/keys

# Run investigation
counsel investigate /mnt/evidence \
  --signing-key ~/.counsel/keys/counsel_signing.pem \
  --output-dir ./results

# Replay any finding
counsel replay results/<run-id>/counsel-ledger.jsonl <seq>

# Red-team tests
counsel redteam /mnt/evidence
```

---

## Architecture

```
[ Launcher ] ──spawns──> [ MCP Server ] <──stdio──> [ Agent: Claude Opus 4.8 ]
  signs manifest            10 typed tools              MCP-only, no shell
  holds signing key         parse-before-return         adaptive thinking
  read-only mount           appends to ledger           cannot sign
        |                        |
        v                        v
  [ Verifier ]            [ Ledger JSONL ]
  Ed25519 sign            hash-chained
  chain verify            append-only
  hash_in == hash_out     replay command
```

**Three trust boundaries (architectural, not prompt-based):**
- B1: Agent reaches evidence ONLY through typed MCP functions
- B2: Signing key lives in Launcher/Verifier; agent cannot sign
- B3: Agent has no shell, no exec, no write mount

---

## The 5-State Claim Model

| State | Meaning | Support Threshold |
|---|---|---|
| OBSERVED | Single artifact noted | Any signal |
| INFERENCE | Some support, below threshold | 0 < support < 0.80 |
| CORROBORATED | 2+ independent sources agree | support >= 0.80 AND >= 2 independent groups |
| CONTRADICTED | Evidence actively conflicts | contradiction >= 0.60 |
| UNRESOLVED | Bounded search exhausted | No gaps remain, still undecided |

The engine (not the LLM) computes state. The agent can propose, the engine resolves.

---

## MCP Tool Catalog

| ID | Function | Evidentiary Meaning | Independence Note |
|---|---|---|---|
| T1 | `registry_run_keys` | persistence_configured | Registry hive |
| T2 | `prefetch_run_record` | payload_executed (strong) | Prefetch subsystem |
| T3 | `amcache_lookup` | payload_executed (medium) | **Independent of T2** (kernel loader) |
| T4 | `fs_stat_hash` | payload_present + signature | Direct filesystem |
| T5 | `mft_timeline` | timeline backbone | NTFS journal |
| T6 | `yara_scan` | malware identity | Pattern matching |
| T7a | `mem_pslist` | payload_active (strong) | **Independent of all disk** |
| T7b | `mem_netscan` | C2/exfil | Memory network tables |
| T8 | `mem_malfind` | defense_evasion | Memory anomaly |
| T9 | `net_flows` | C2_communication, exfiltration | **Independent of memory** (PCAP) |
| T10 | `evtx_query` | logon/service/exec events | Event log subsystem |

All tools: parse-before-return, typed output, no shell, ledger-appending.

---

## Corroboration Rule DSL

```yaml
rule: persistence_via_run_key
emits: [persistence_configured, payload_present, payload_executed, payload_active]
signals:
  - artifact: registry.run_keys
    supports: persistence_configured
    weight: 0.95
    independent_of: registry.run_keys

  - artifact: prefetch.run_record
    supports: payload_executed
    weight: 0.90
    independent_of: prefetch.run_record

  - artifact: amcache.lookup
    supports: payload_executed
    weight: 0.60
    independent_of: prefetch.run_record  # <-- different independence group
    requires: "linked_pe == true"

contradictions:
  - artifact: fs.stat_hash
    weight: 0.75
    requires: "exists == false"

modifiers:
  - artifact: fs.stat_hash
    effect: benign_indicator
    requires: "signed == true"
    note: "Signed binary - LOLBin abuse still possible"

provenance: "SANS FOR500; MITRE ATT&CK T1547.001; Zimmerman PECmd + AmcacheParser"
```

Bad rules fail at load time (fail-closed). Add rules by dropping `.yaml` files in `rules/`.

---

## Red-Team Test Suite

| Test | Attack | Result |
|---|---|---|
| RT1 | Shell escape via tool argument | REJECTED (no shell primitive) |
| RT2 | Prompt injection via filename | IGNORED (sanitize_string barrier) |
| RT3 | Prompt injection via file content | IGNORED (typed fields, not instructions) |
| RT4 | Write capability probe | NO_WRITE_TOOLS |
| RT5 | Spoliation attempt | WRITE_BLOCKED (read-only mount) |
| RT6 | Ledger tamper detection | DETECTED (hash chain fails) |
| RT7 | Evidence image tamper | DETECTED (SHA256 mismatch) |

Run: `counsel redteam /mnt/evidence`

---

## Accuracy Report

Benchmarked on "Stolen Szechuan Sauce" forensic case (locked answer key, June 2026).

| Metric | COUNSEL | Baseline Protocol SIFT |
|---|---|---|
| Precision | TBD after SIFT run | TBD |
| Recall | TBD | TBD |
| FPR | TBD | TBD |
| Hallucination Rate | TBD | TBD |
| ECE | TBD | TBD |

Full report: `docs/accuracy-report.md`

---

## Devpost Submission Components

- [x] Code Repository (this repo, MIT license)
- [ ] Demo Video (5-minute narrated terminal screencast)
- [x] Architecture Diagram (`docs/architecture.md`)
- [x] Written Description (`docs/written-description.md`)
- [x] Dataset Documentation (`docs/dataset-docs.md`)
- [ ] Accuracy Report (`docs/accuracy-report.md`) - after SIFT run
- [x] Try-It-Out Instructions (this README Quick Start)
- [ ] Agent Execution Logs - after SIFT run

---

## License

MIT License - Copyright 2026 COUNSEL Contributors

Built with: Claude Opus 4.8 (Anthropic), MCP, SANS SIFT Workstation, Eric Zimmerman Tools,
Volatility 3, tshark, Rich, Jinja2, cryptography (Ed25519)
