# Write Your First COUNSEL Corroboration Rule in 5 Minutes

COUNSEL's corroboration rules are a declarative YAML DSL.
No Python required. Drop a `.yaml` file in the `rules/` directory
and reload the agent. Bad rules fail at load time - they never silently break.

## Anatomy of a Rule

```yaml
rule: my_rule_name            # unique snake_case ID
emits: [claim_type_1, ...]    # which claim types this rule can produce
signals:                      # evidence that SUPPORTS these claims
  - artifact: tool.name       # which MCP tool provides this signal
    supports: claim_type      # which claim type this signal supports
    weight: 0.80              # how strongly (0.0 to 1.0)
    independent_of: tool.name # if omitted, defaults to same as artifact (fully independent)
    requires: "field OP value" # optional predicate (see below)

contradictions:               # evidence that CONTRADICTS (optional)
  - artifact: tool.name
    weight: 0.75
    requires: "exists == false"

modifiers:                    # context that changes interpretation (optional)
  - artifact: tool.name
    effect: benign_indicator  # or: suspicion
    requires: "signed == true"
    note: "LOLBin abuse possible"

provenance: "SANS FOR500 Module 3; MITRE ATT&CK T1547.001"  # REQUIRED - cite your source
```

## Step 1: Pick your claim type

Available claim types:
- `persistence_configured`
- `payload_present`
- `payload_executed`
- `payload_active`
- `lateral_movement`
- `credential_access`
- `exfiltration`
- `c2_communication`
- `defense_evasion`
- `discovery`

## Step 2: Pick your artifact signals

Available MCP tools (these are the `artifact:` values):
- `registry.run_keys`
- `prefetch.run_record`
- `amcache.lookup`
- `fs.stat_hash`
- `mft.timeline`
- `yara.scan`
- `mem.pslist`
- `mem.netscan`
- `mem.malfind`
- `net.flows`
- `evtx.query`

## Step 3: Think about independence

**This is the most important step.** For a claim to reach CORROBORATED,
it needs two or more INDEPENDENT signal groups.

Ask yourself: "If this source is wrong, would the other source also be wrong?"

Examples of independent pairs:
- `prefetch.run_record` + `amcache.lookup` - INDEPENDENT (different OS subsystems)
- `mem.pslist` + `fs.stat_hash` - INDEPENDENT (memory vs. disk)
- `net.flows` + `mem.netscan` - INDEPENDENT (PCAP vs. memory tables)

Examples of DEPENDENT pairs (DON'T call them independent):
- `prefetch.run_record` + `prefetch.run_record` (same tool twice)
- `mem.pslist` + `mem.malfind` (same Volatility run, shared code path)

Use `independent_of: other_tool` to put signals in the SAME group (co-dependent).
Signals without `independent_of` are independent by default.

## Step 4: Write predicates (optional)

Predicates filter whether a signal applies:

```yaml
requires: "exists == true"       # field must be true
requires: "exists == false"      # field must be false (use for contradictions!)
requires: "is_external == true"  # filter external connections
requires: "linked_pe == true"    # Amcache has SHA1 (real PE execution)
requires: "signed == false"      # unsigned binary (more suspicious)
```

Supported operators: `==`, `!=`, `>`, `>=`, `<`, `<=`, `IN`, `NOT_IN`

## Step 5: Cite your provenance

The `provenance:` field is REQUIRED. Bad rules that omit it fail at load time.

Good provenance:
```yaml
provenance: "SANS FOR508 Memory Forensics; Volatility malfind docs; MITRE ATT&CK T1055"
```

Cite the primary DFIR source (SANS course, Zimmerman tool docs, MITRE ATT&CK).

## Full Example: Detecting Scheduled Task Persistence

```yaml
rule: persistence_via_scheduled_task
emits: [persistence_configured, payload_executed]
signals:
  - artifact: evtx.query
    supports: persistence_configured
    weight: 0.88
    independent_of: evtx.query

  - artifact: registry.run_keys
    supports: persistence_configured
    weight: 0.60
    independent_of: evtx.query

  - artifact: prefetch.run_record
    supports: payload_executed
    weight: 0.85
    independent_of: prefetch.run_record

  - artifact: fs.stat_hash
    supports: payload_present
    weight: 0.70
    independent_of: fs.stat_hash
    requires: "exists == true"

contradictions:
  - artifact: fs.stat_hash
    weight: 0.80
    requires: "exists == false"

modifiers:
  - artifact: fs.stat_hash
    effect: benign_indicator
    requires: "signed == true"
    note: "Microsoft-signed scheduled tasks exist - check task content"

provenance: "SANS FOR508; Windows Task Scheduler forensics; MITRE ATT&CK T1053.005; EventID 4698 (task created)"
```

## Load and Test

```bash
# Put your rule in rules/
cp my_rule.yaml counsel/rules/

# Validate (rules fail-closed on bad syntax)
python -c "
from counsel.engine.dsl import RuleRegistry
from pathlib import Path
r = RuleRegistry()
r.load_directory(Path('counsel/rules'))
print('Rules loaded:', len(r.all_rules()))
"

# Run investigation - your rule is active
counsel investigate /mnt/evidence
```

## Common Mistakes

| Mistake | Effect | Fix |
|---|---|---|
| Missing `provenance` | Load-time error | Add citation |
| `independent_of` set to same tool | All signals in one group, can never reach CORROBORATED | Use different tool or remove `independent_of` |
| `weight` > 1.0 | Load-time error | Keep in [0.0, 1.0] |
| Unknown `artifact` tool name | Load-time error | Check the tool catalog above |
| Unknown `claim_type` | Load-time error | Check available claim types above |
| `requires` field not in tool's output | Predicate always returns False | Check the tool's typed output schema |
