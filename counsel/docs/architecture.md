# COUNSEL Architecture

## Process Topology

```
                    +------------------+
                    |  Trusted Launcher |  (holds signing key — agent never sees it)
                    |  - mounts evidence|
                    |    read-only      |
                    |  - computes hash_in|
                    |  - spawns MCP srv |
                    |  - calls Verifier |
                    +--------+---------+
                             |
                    spawns, passes run_id + env
                             |
               +-------------|-------------+
               |             v             |
    +----------+----------+  stdio  +--------------+
    |    MCP Server        |<------->|  Agent Runtime|
    |  - 10 typed tools   |         |  Claude Opus 4.8
    |  - parse-before-     |         |  - MCP-only tools
    |    return            |         |  - adaptive thinking
    |  - read-only fs      |         |  - NO shell
    |  - appends to ledger |         |  - NO write mount
    |  - no shell          |         |  - CANNOT sign
    +----------+-----------+         +--------------+
               |
               v
    +----------+-----------+
    |   Ledger (JSONL)      |
    |   - append-only       |
    |   - hash-chained      |
    |   - sha256(prev|entry)|
    +----------+-----------+
               |
    (after agent exit)
               |
               v
    +----------+-----------+
    |   External Verifier   |
    |   - reads ledger      |
    |   - recomputes chain  |
    |   - hash_out == hash_in|
    |   - Ed25519 signs     |
    |     manifest          |
    +----------------------+
```

## Trust Boundaries

### B1 — Evidence/Agent Boundary
The agent reaches evidence ONLY through typed MCP function calls.
There is no file-read tool, no shell tool, no directory-listing tool.
Even if the agent's reasoning were compromised, it has no path to read
arbitrary bytes from the evidence image.

**Enforcement**: MCP server exposes 10 typed functions. Agent is configured
with ONLY those tools. No `bash` tool. No `read_file` tool.

### B2 — Ledger/Signing Boundary
The agent can APPEND to the ledger (via MCP server's ledger integration)
but CANNOT SIGN. The Ed25519 private key lives in the Launcher/Verifier
only — the agent process never has it in its environment.

**Enforcement**: Signing happens in the Verifier, a separate process that
runs AFTER agent exit. Signed manifest states: chain_valid + evidence_intact.

### B3 — Agent/Host Boundary
The agent runtime has no shell, no arbitrary exec, no write mount.
Even a fully successful prompt injection attack has no dangerous primitive
to call. Capability isolation is the primary defense.

**Enforcement**: Claude Code configured without bash/shell tools.
Evidence mount is read-only at the OS level (mount -o ro).
MCP server tools are all read-only forensic parsers.

## Data Flow

```
Evidence Image
    |
    | (read-only, via MCP tools)
    v
MCP Server (parse-before-return)
    |
    | TypedRecord { records, artifact_path, offset, raw_sha256, parse_quality }
    v
Agent (Claude Opus 4.8)
    |
    | Reads claim state from corroboration engine
    v
Corroboration Engine
    |
    | noisy-OR(independent groups) -> support, contradiction -> state
    v
Claim { state: OBSERVED|INFERENCE|CORROBORATED|CONTRADICTED|UNRESOLVED }
    |
    | If state changed: record StateChange in claim history
    v
Ledger (hash-chained JSONL)
    |
    | (after agent exit)
    v
Verifier: verify chain + re-hash evidence + Ed25519 sign manifest
    |
    v
Signed Case Package (ledger + manifest + signature + HTML report)
```

## Prompt-Injection Resistance

Two-layer defense:

1. **Parse-Before-Return (MCP layer)**: Raw forensic tool output is parsed into
   typed record dicts before returning to the LLM. String fields are bounded
   to 512 chars and control characters are stripped. The LLM sees structured
   data, not freeform strings from adversarial artifacts.

2. **Capability Isolation (agent layer)**: Even if an injection in artifact content
   successfully manipulates the agent's reasoning, the agent has NO exec primitive,
   NO write primitive, and NO shell. There is nothing dangerous to call.
   The architecture holds because the primitives don't exist.

This directly addresses the GTG-1002 "weaponized AI" threat scenario.

## Confidence Model

Noisy-OR over independence groups:

```
For claim C under rule R:
  groups = partition(signals(C)) by independent_of field
  eff_w(g) = max over s in g of (w_s * parse_quality_s)
  support(C) = 1 - PRODUCT over groups g of (1 - eff_w(g))
  contradiction(C) = max over contradicting signals of (w * parse_quality)

  state(C):
    contradiction >= 0.60 AND contradiction > support  -> CONTRADICTED
    support >= 0.80 AND active independent groups >= 2  -> CORROBORATED
    0 < support < 0.80                                  -> INFERENCE
    all signals observed, support == 0                  -> UNRESOLVED
    gaps remain                                         -> OBSERVED
```

The independence requirement (>= 2 groups for CORROBORATED) is the
anti-hallucination core: one confident tool is NEVER enough.
