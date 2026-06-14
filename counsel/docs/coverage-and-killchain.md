# Coverage and Kill-Chain Reconstruction

This document answers the "Breadth and Depth of Analysis" judging criterion:
*how much case data can the agent handle, and how deep does the analysis go?*

COUNSEL's design choice is **depth over surface breadth**: a focused set of
forensic artifact families, each parsed into typed records, cross-corroborated by
a declarative rule engine, and reconstructed into a single temporal attack story.

---

## 1. Breadth - artifact coverage matrix

Eleven typed MCP tools span four forensic data domains. Each feeds the
corroboration engine as an **independent evidence group** (the unit the noisy-OR
math reasons over), so a claim is only CORROBORATED when groups from *different*
domains agree.

| Data domain | MCP tool | Artifact parsed | Primary claim(s) supported | MITRE |
|-------------|----------|-----------------|----------------------------|-------|
| Disk / registry | `registry.run_keys` | Run/RunOnce hives | persistence_configured | T1547.001 |
| Disk / execution | `prefetch.run_record` | `*.pf` prefetch | payload_executed | T1059 |
| Disk / filesystem | `mft.timeline` | `$MFT` records | payload_present, defense_evasion | T1105, T1036 |
| Disk / registry | `amcache.lookup` | Amcache.hve | payload_executed | T1059 |
| Disk / filesystem | `fs.stat_hash` | File stat + SHA256 | payload_present, defense_evasion | T1105, T1036 |
| Disk / content | `yara.scan` | YARA over file bytes | payload_present | T1105 |
| Memory / process | `mem.pslist` | Process list | payload_active | T1055 |
| Memory / network | `mem.netscan` | Socket table | c2_communication, exfiltration | T1071, T1041 |
| Memory / injection | `mem.malfind` | Injected RWX regions | payload_active, defense_evasion | T1055, T1036 |
| Network / flows | `net.flows` | Netflow / pcap | c2_communication, exfiltration | T1071, T1041 |
| Logs / events | `evtx.query` | Windows EVTX | discovery, lateral_movement(*) | T1083, T1021 |

(*) `lateral_movement` is **emitted** from EVTX but the engine CONTRADICTS it - see below.

**Independence is the point.** `c2_communication` reaching CORROBORATED requires
agreement across the *memory* socket table (`mem.netscan`) and the *network* flow
record (`net.flows`) - two domains, two acquisition methods. One alone yields only
INFERENCE.

---

## 2. Depth - reconstructed kill chain (SANS Szechuan Sauce)

From the same run, COUNSEL's corroborated findings reassemble into a coherent
ATT&CK kill chain on host MORTY-PC. Every step below is traceable to a specific
tool execution in the signed ledger (seq numbers in the case file).

| # | Time (2017-10-04) | Tactic / Technique | What COUNSEL corroborated | Independent sources |
|---|-------------------|--------------------|---------------------------|---------------------|
| 1 | (boot persistence) | Persistence / T1547.001 | `wupd.exe` registered in a Run key | registry.run_keys + prefetch.run_record |
| 2 | 14:22:18 | Execution / T1059 | `wupd.exe` executed from `\Temp\` | prefetch + mft + evtx(4688) + amcache |
| 3 | 14:22:21 | C2 / T1071 | Beacon to `185.220.101.47:4444` (ESTABLISHED) | mem.netscan + net.flows |
| 4 | 14:23:10 | Defense Evasion / T1036 | `svchost32.exe` masquerade dropped to `\Roaming\` | mft + fs.stat_hash + mem.malfind |
| 5 | (session) | Discovery / T1083 | File/dir enumeration | prefetch + mem.pslist + evtx |
| 6 | (session) | Process Injection / T1055 | Injected RWX region in `wupd.exe` PID | mem.pslist + mem.netscan |
| 7 | (session) | Exfiltration / T1041 | `*_CONFIDENTIAL.zip` / `*_ULTRA_SECRET.docx` over the C2 channel | mem.pslist + mem.netscan |

This is the analyst's actual deliverable: not a list of artifacts, but **a story
with corroborated provenance at every node.**

---

## 3. Depth - what was deliberately NOT asserted

Depth also means knowing where to stop. On the same evidence COUNSEL **withheld**
the two claims a keyword-matching tool would have asserted:

- **`lateral_movement` -> CONTRADICTED.** EVTX contains logon/auth keywords, but an
  independent higher-weight signal refutes host-to-host movement. The engine marks
  it CONTRADICTED rather than letting the keyword presence stand.
- **`credential_access` -> WITHHELD (INFERENCE).** A single artifact family hints at
  it, but no second independent group corroborates `lsass_injection` or `hive_access`
  on the typed fields, so it never reaches CORROBORATED.

These two are the case's true negatives. Withholding them is what takes accuracy
from "recall 1.0, FPR 1.0" (naive) to "recall 1.0, FPR 0.0" (COUNSEL).

---

## 4. Generalization beyond one case

The engine is **case-independent**: rules live in `rules/*.yaml`, tools are typed
MCP functions, and nothing about the kill chain above is hard-coded. The same
pipeline runs unchanged on:

- `counsel/fixtures/szechuan_sauce` - the kill chain above.
- `counsel/fixtures/adversarial_injection` - identical artifacts whose text fields
  carry a prompt-injection payload; the engine still withholds `credential_access`,
  proving the guardrail is architectural, not lexical.

Adding a new case is a fixture directory; adding a new artifact family is one YAML
rule plus one typed parser. Real disk/memory images run through the identical path
on the SIFT Workstation (`counsel investigate /mnt/evidence`).
