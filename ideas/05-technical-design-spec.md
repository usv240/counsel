# 05 - COUNSEL Technical Design Spec (deep)

The buildable engineering spec. ASCII-only. Pairs with 06 (UI/UX) and 07 (eval + threat model).

## 0. Process topology & trust boundaries
Four OS processes with distinct privilege. The boundary IS the security argument.
```
  [ Trusted Launcher ]  (holds signing key; agent never sees it)
        | spawns, passes run_id, mounts evidence read-only
        v
  [ MCP Server ]  <--stdio/socket-->  [ Agent Runtime: Claude Code ]
   read-only fs,                       MCP-only tools, NO shell tool,
   parse-before-return,                NO network egress except model API
   appends to ledger                   cannot write evidence or sign
        |
        v
  [ Verifier ]  (separate; reads ledger after exit, validates chain, signs manifest)
```
Trust boundaries to draw in the architecture diagram:
- B1 evidence/agent: agent reaches evidence ONLY through typed MCP reads (architectural, not prompt).
- B2 ledger/signing: agent appends but cannot sign; key lives in Launcher/Verifier only.
- B3 agent/host: agent runtime has no shell, no arbitrary exec, no write mount.

## 1. MCP server design
Principles: (a) typed functions, not `execute_shell`; (b) parse-before-return (never dump raw
megabytes into context); (c) every call appends a ledger entry; (d) deterministic + idempotent;
(e) returns structured records + a pointer (path+offset+raw_output_sha256) for traceability.

### 1.1 Common return envelope (every tool)
```json
{ "tool": "prefetch.run_record", "run_id": "...", "seq": 42,
  "records": [ { ...typed fields... } ],
  "evidence": { "path": "/img/C/Windows/Prefetch/EVIL.EXE-1A2B.pf",
                "offset": 12480, "raw_output_sha256": "9d1c..." },
  "parse_quality": 0.97, "warnings": ["..."], "truncated": false }
```

### 1.2 Tool catalog (build order: T1-T4 MVP, then T5-T10)
| ID | Function | Key typed output | Evidentiary meaning |
|---|---|---|---|
| T1 | `registry.run_keys()` | {hive, key, value_name, command, last_write} | persistence_configured |
| T2 | `prefetch.run_record(name)` | {exe, run_count, last_run[], volumes} | payload_executed (strong) |
| T3 | `amcache.lookup(name|sha1)` | {path, sha1, first_seen, linked_pe} | payload_executed (medium, independent of T2) |
| T4 | `fs.stat_hash(path)` | {exists, size, sha256, timestamps, signed?} | payload_present + signature modifier |
| T5 | `mft.timeline(filter)` | {ts, path, action, MACB, source} | timeline backbone |
| T6 | `yara.scan(path|pid, rules)` | {rule, offsets, strings} | malware identity |
| T7 | `mem.pslist()` / `mem.netscan()` | {pid, ppid, name, path} / {laddr,raddr,state} | payload_active (strong) |
| T8 | `mem.malfind()` | {pid, region, protection, hexdump} | injected code |
| T9 | `net.flows(filter)` | {ts, src, dst, port, bytes, proto, sni} | C2 / exfil corroboration |
| T10| `evtx.query(filter)` | {channel, eid, ts, fields} | logon/service/exec events |
Each tool documents: input schema, output schema, the artifact it reads, parse-confidence
heuristic, and which claim(s) it can support/contradict (machine-readable, consumed by the DSL).

## 2. Corroboration rule DSL (the community-IP contribution)
A declarative YAML language compiled to an evaluator. Grammar (informal EBNF):
```
rule        := "rule:" ID
               "emits:" "[" claim_type {"," claim_type} "]"
               "signals:" signal+
               ["modifiers:" modifier+]
               ["contradictions:" signal+]
               "provenance:" STRING
signal      := "- artifact:" tool_record  "supports:" claim_type
               "weight:" FLOAT[0..1]  ["independent_of:" tool_record]
               ["requires:" predicate]
modifier    := "- artifact:" tool_record  "effect:" ("benign_indicator"|"suspicion")
               ["note:" STRING]
predicate   := field OP value   (e.g. path NOT_IN system_dirs ; signed == false)
```
Example (the spine of the demo):
```yaml
rule: persistence_via_run_key
emits: [persistence_configured, payload_present, payload_executed, payload_active]
signals:
  - { artifact: registry.run_keys,    supports: persistence_configured, weight: 0.95 }
  - { artifact: fs.stat_hash,         supports: payload_present,        weight: 0.60 }
  - { artifact: prefetch.run_record,  supports: payload_executed,       weight: 0.90 }
  - { artifact: amcache.lookup,       supports: payload_executed,       weight: 0.50,
      independent_of: prefetch.run_record }
  - { artifact: mem.pslist,           supports: payload_active,         weight: 0.90 }
  - { artifact: net.flows,            supports: payload_active,         weight: 0.55,
      independent_of: mem.pslist, requires: "raddr NOT_IN known_good" }
contradictions:
  - { artifact: fs.stat_hash, supports: payload_present, weight: 0.6, requires: "exists == false" }
modifiers:
  - { artifact: fs.stat_hash, effect: benign_indicator, requires: "signed == true",
      note: "LOLBin / signed-proxy abuse possible; never resolves benign alone" }
provenance: "SANS FOR500; Zimmerman PECmd & AmcacheParser docs; MITRE T1547.001"
```
Rule compiler validates: every `artifact` exists in the tool catalog; weights in [0,1];
claim_types are registered; provenance non-empty. Bad rules fail at load (fail-closed).

## 3. Data model
```
Claim   { id, type, subject, time?, state, support, contradiction,
          evidence:[EvidenceRef], rule_id, history:[StateChange] }
EvidenceRef { ledger_seq, tool, artifact_path, offset, raw_sha256, weight, independent_group }
StateChange { ts, from_state, to_state, trigger, iteration }   # powers "self-correction" UI
ClaimGraph  { nodes:[Claim|Entity], edges:[supports|contradicts|configures|executed|active] }
```

## 4. Confidence model & state resolution
Noisy-OR over independent supporting signals; co-dependent signals share one group and
contribute once at their max.
```
For claim C:
  groups = partition(signals(C)) by independent_group        # co-dependent share a group
  eff_w(g) = max over s in g of (w_s * r_s)                  # r_s = parse_quality * quality flags
  support(C)       = 1 - PRODUCT over groups g of (1 - eff_w(g))
  contradiction(C) = max over conflicting signals of (w * r)

  state(C):
    contradiction >= TAU_CONTRA (0.6)                  -> Contradicted
    support >= TAU_CORROB (0.8) AND >=2 indep groups   -> Corroborated
    0 < support < TAU_CORROB                            -> Inference
    support == 0 after bounded search                   -> Unresolved
    single direct artifact, no corroboration yet        -> Observed
```
Thresholds TAU_* are config, tuned on the ground-truth case (see 07 calibration). Independence
requiring >=2 groups for Corroborated is the anti-hallucination core: one confident tool is never
enough.

## 5. Agent loop & autonomous control (Claude Code)
State machine, bounded, with explicit termination. This is where Criterion 1 is won.
```
INIT -> TRIAGE -> {PROPOSE -> VERIFY -> (GAP? GATHER : RULE)} loop -> SYNTHESIZE -> SIGN -> REPORT
```
- TRIAGE: cheap broad sweep (run keys, services, recent execution) to seed hypotheses.
- PROPOSE: agent emits a structured Claim with citation + intended next tool + WHY (logged).
- VERIFY: corroboration engine computes support/contradiction/state deterministically.
- GAP DETECTION: if state is Observed/Inference and an *independent* high-weight signal is
  available but unchecked -> that gap is the next action. This drives SELF-CORRECTION without a
  second LLM.
- GATHER: call the gap-filling tool; re-VERIFY; record StateChange (the on-camera ruling change).
- Tool-failure policy: on tool error -> log, mark signal unavailable, try the next-best
  independent signal; never crash the loop.
- Termination (bounded): stop when (no Inference/Observed claims have unexplored independent
  signals) OR iteration == MAX_ITERS OR token_budget exhausted -> graceful SYNTHESIZE with
  remaining claims left Unresolved (honest).
- Determinism aids: temperature low for control decisions; the *engine* (not the LLM) sets states.

### 5.1 Prompt-injection / evidence-hijack resistance
Evidence is hostile input. Defenses:
- MCP returns typed records; raw strings from evidence are wrapped/escaped and never interpreted
  as instructions (delivered as data fields, not as agent directives).
- Agent has no shell/exec/write capability, so even a fully successful injection has no dangerous
  primitive to call (capability isolation = the real defense).
- A canary test (07) plants an injection payload in the evidence; expected result: ignored / no
  capability available. This directly addresses the weaponized-AI (GTG-1002) threat.

## 6. Ledger & signing protocol (court-grade audit)
- Append-only JSONL; entry schema in 02/04. `entry_hash = sha256(prev_hash || canonical(entry))`.
- Genesis entry pins: evidence image sha256 (in), tool catalog hash, rule set hash, run_id.
- Agent CANNOT sign. After agent exit, Verifier: recomputes the full chain, re-hashes evidence
  (hash out == hash in -> integrity attestation), then signs the manifest
  `{run_id, chain_head_hash, evidence_sha256_in, evidence_sha256_out, ts}` with an Ed25519 key
  held outside the agent runtime.
- `replay(seq)`: re-executes that entry's exact tool+args, recomputes raw_output_sha256, asserts
  equality -> reproducibility on demand (Criterion 5 wow).
- `export-case`: bundles ledger + signature + manifest + report into a verifiable archive.

## 7. Stack & repo layout
```
counsel/
  launcher/        # trusted launcher: mounts ro, spawns, holds run policy
  mcp_server/      # FastMCP (Python); tools/ one module per tool; parsers/
  engine/          # rule loader+compiler, confidence model, state machine
  rules/           # *.yaml corroboration rules (the DSL content)
  ledger/          # append, hash-chain, verify, replay, export
  verifier/        # external chain verify + Ed25519 sign
  agent/           # Claude Code config, system prompt, loop policy, budgets
  report/          # ledger -> TUI (rich) + static HTML Case File generator
  bench/           # ground-truth harness, metrics, calibration (see 07)
  redteam/         # spoliation / shell-escape / injection / tamper tests (see 07)
  docs/            # README, architecture diagram, threat model, accuracy report
```
Backing tools on SIFT: Eric Zimmerman tools (PECmd/AmcacheParser/RECmd) or analyzeMFT/regipy,
Volatility 3, Zeek/tshark, yara. MCP server wraps these and parses their output to typed records.
```
```
