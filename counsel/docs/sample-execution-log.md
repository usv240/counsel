# Sample Agent Execution Log

This document shows the structure of a COUNSEL ledger and what an investigation looks like
in fixture mode against the Stolen Szechuan Sauce scenario.

**To generate a real log:** `COUNSEL_FIXTURE_DIR=counsel/fixtures/szechuan_sauce counsel investigate counsel/fixtures/szechuan_sauce --skip-hash`

---

## Ledger Schema

Every entry in `counsel-ledger.jsonl` has this structure:

```json
{
  "seq": <int>,
  "entry_type": "genesis|tool_call|claim_state|agent_decision|halt",
  "run_id": "<uuid>",
  "ts": "<iso8601>",
  "prev_hash": "<sha256-hex-64>",
  "entry_hash": "<sha256-hex-64>",
  "payload": { ... }
}
```

`entry_hash = SHA256(prev_hash + canonical_json_of_entry)` — every entry is chained to its predecessor.

There are exactly five entry types:

| Type | Written by | Purpose |
|---|---|---|
| `genesis` | Launcher (pre-run) | Pins evidence SHA256, tool catalog hash, rule set hash |
| `tool_call` | MCP server | Records every forensic tool invocation + raw output SHA256 |
| `claim_state` | Launcher (post-run) | Records every INFERENCE→CORROBORATED (and other) transitions |
| `agent_decision` | *(reserved — not currently written)* | Agent reasoning trace |
| `halt` | Launcher (post-run) | Termination reason, final counts, elapsed time |

---

## Annotated Fixture-Mode Run

The hashes below are real SHA256 values computed by the ledger machinery
when run against the fixture files. Run the tool yourself to get live values.
These are abbreviated to `<sha256:first16>…` for readability.

```
seq=0  entry_type=genesis
  payload:
    evidence_sha256_in: "FIXTURE_MODE"   (--skip-hash was used)
    tool_catalog_hash:  "tool_catalog_v1"
    rule_set_hash:      <sha256 of all 8 loaded rule YAML files>
  entry_hash: <sha256:...>

  [MCP server subprocess starts here; resumes from seq=1]

seq=1  entry_type=tool_call            <-- written by MCP server
  payload:
    tool:              "registry.run_keys"
    artifact_path:     "counsel/fixtures/szechuan_sauce/registry_run_keys.json"
    raw_output_sha256: <sha256 of raw fixture bytes>
    parse_quality:     1.0
    record_count:      3
    truncated:         false
    warnings:          ["[FIXTURE] Pre-recorded output. Replace with a real SIFT run."]
  entry_hash: <sha256:...>

seq=2  entry_type=tool_call
  payload:
    tool:              "prefetch_run_record"
    artifact_path:     "counsel/fixtures/szechuan_sauce/prefetch_run_record.json"
    raw_output_sha256: <sha256:...>
    parse_quality:     1.0
    record_count:      3
    truncated:         false

seq=3  entry_type=tool_call
  payload:
    tool:              "amcache_lookup"
    artifact_path:     "counsel/fixtures/szechuan_sauce/amcache_lookup.json"
    raw_output_sha256: <sha256:...>
    parse_quality:     1.0
    record_count:      4

  [open_gaps returned to agent after seq=3:
    {tool: "amcache_lookup", weight: 0.65, for_claim: "payload_executed", claim_state: "INFERENCE",
     note: "Unchecked independent signal — calling this moves payload_executed toward CORROBORATED"}
   → agent calls amcache_lookup next: self-correction demonstrated]

seq=4  entry_type=tool_call
  payload:
    tool:              "fs_stat_hash"
    raw_output_sha256: <sha256:...>
    record_count:      1

seq=5  entry_type=tool_call
  payload:
    tool:              "yara_scan"
    raw_output_sha256: <sha256:...>
    record_count:      2

seq=6  entry_type=tool_call
  payload:
    tool:              "mem_pslist"
    raw_output_sha256: <sha256:...>
    record_count:      6

seq=7  entry_type=tool_call
  payload:
    tool:              "mem_netscan"
    raw_output_sha256: <sha256:...>
    record_count:      3

seq=8  entry_type=tool_call
  payload:
    tool:              "net_flows"
    raw_output_sha256: <sha256:...>
    record_count:      4

seq=9  entry_type=tool_call
  payload:
    tool:              "evtx_query"
    raw_output_sha256: <sha256:...>
    record_count:      8

  [MCP server subprocess exits; Launcher writes post-run entries]

seq=10  entry_type=claim_state         <-- written by Launcher post-run
  payload:
    claim_id:        "a1b2c3d4"
    claim_type:      "payload_executed"
    subject:         "investigation_subject"
    from_state:      "INFERENCE"
    to_state:        "CORROBORATED"
    support:         0.967
    contradiction:   0.0
    rule_id:         "payload_execution_chain"
    trigger:         "amcache_lookup result"
    iteration:       3

seq=11  entry_type=claim_state
  payload:
    claim_type:  "payload_present"
    from_state:  "INFERENCE"
    to_state:    "CORROBORATED"
    support:     0.993
    trigger:     "yara_scan result"

seq=12  entry_type=claim_state
  payload:
    claim_type:  "c2_communication"
    from_state:  "INFERENCE"
    to_state:    "CORROBORATED"
    support:     0.987
    trigger:     "mem_netscan result"

seq=13  entry_type=halt
  payload:
    reason:               "all_claims_settled"
    iteration:            9
    open_claims:          0
    corroborated_claims:  5
    elapsed_seconds:      <actual runtime>
```

---

## Replay Verification

`counsel replay` verifies that re-running a tool produces the same raw output SHA256 recorded
in the ledger. It only works on `tool_call` entries (seq 1–9 in this run).

```bash
# Replay seq=2 (prefetch_run_record) and verify raw output hash
counsel replay counsel-output/<run-id>/counsel-ledger.jsonl 2 \
  --evidence counsel/fixtures/szechuan_sauce/

# Expected output:
# Replaying seq=2: tool=prefetch_run_record
# Original SHA256:  <sha256 from ledger>
# Replayed SHA256:  <sha256 from re-run>
# Match:            true
# Verdict:          REPRODUCED
```

Replaying a `claim_state` or `halt` entry returns `NOT_A_TOOL_CALL` by design —
only tool executions are replayable.

---

## Chain Verification

```bash
counsel verify-package counsel-output/<run-id>/counsel_case_<run-id>.tar.gz \
  ~/.counsel/keys/counsel_signing_pub.pem
```

This recomputes `SHA256(prev_hash + canonical_json)` for every entry and confirms
the stored `entry_hash` matches. Any post-hoc modification of any entry fails this check.
