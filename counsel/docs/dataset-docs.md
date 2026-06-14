# Dataset Documentation - COUNSEL Benchmark

## Primary Case: "Stolen Szechuan Sauce"

**Source**: Dfir.training / Dave Cowen (2018)
**Type**: Windows forensic image (.E01)
**Size**: ~8GB compressed image
**OS**: Windows 10 / Windows 7 (check image metadata)
**Scenario**: Employee (Rick) exfiltrated proprietary sauce recipe via a C2 implant

### How to Obtain

The "Stolen Szechuan Sauce" case image is publicly available for forensic training:

1. Visit: https://dfir.training/2018/09/19/stolen-szechuan-sauce-digital-forensics-challenge/
2. Download the challenge image (free registration may be required)
3. Verify SHA256 against published hash
4. Mount read-only: `sudo mount -o ro,loop szechuan_sauce.E01 /mnt/evidence`

### Evidence Artifacts Present

| Artifact | Location | Tool |
|---|---|---|
| Registry hives | Windows/System32/config/{SYSTEM,SOFTWARE} | T1: registry_run_keys |
| NTUSER.DAT | Users/Rick/NTUSER.DAT | T1: registry_run_keys |
| Prefetch files | Windows/Prefetch/*.pf | T2: prefetch_run_record |
| Amcache | Windows/AppCompat/Programs/Amcache.hve | T3: amcache_lookup |
| $MFT | $MFT | T5: mft_timeline |
| Event logs | Windows/System32/winevt/Logs/*.evtx | T10: evtx_query |
| Memory image | (if included - check challenge archive) | T7, T8: mem_* |
| PCAP | (if included - check challenge archive) | T9: net_flows |

### Answer Key (Locked)

The locked answer key for COUNSEL's accuracy benchmark is at:
`counsel/fixtures/szechuan_sauce/answer_key.json`

It was locked before running COUNSEL on the case to prevent post-hoc
rationalization of the benchmark results.

**True Positives (expected CORROBORATED claims)**:
- persistence_configured - Run key in HKCU (wupd.exe)
- payload_present - Malicious wupd.exe on disk
- payload_executed - Confirmed by Prefetch + Amcache (independent subsystems)
- payload_active - Process active in memory + external network connection
- c2_communication - External C2 IP (185.220.101.47) in memory + PCAP

**True Negatives (should NOT be CORROBORATED)**:
- lateral_movement - Single workstation; no lateral movement evidence
- credential_access - No credential dumping evidence

**Deterministic verification (no API key needed)**:
```bash
pytest tests/test_fixture_accuracy.py -v   # 10/10 in ~4 seconds
```

### Privacy and Legal

This is a publicly released forensic training case. The data is synthetic/fictional
(there is no real "Rick" or real Szechuan sauce company). Safe to use for research.

---

## Secondary Case: SANS SRL-2018 (Corporate APT Scenario)

**Source**: SANS Institute SRL-2018 dataset (FOR508 supplemental evidence)
**Type**: E01 disk image + raw memory image
**Disk image**: `base-wkstn-01-c-drive.E01` (15.76 GB, NTFS partition)
**Memory image**: `base-wkstn-01-mem.img` (3.0 GB RAM dump)
**OS**: Windows (corporate workstation, initial alert host in APT scenario)
**Scenario**: Corporate APT - wkstn-01 is the beachhead. The attacker moved laterally
to the domain controller and exfiltrated data. COUNSEL investigates this initial
alert host.

**Purpose**: Demonstrates COUNSEL generalizes to a new, completely different case
without any rule changes. The same 8 YAML corroboration rules, same 11 MCP tools,
same corroboration engine -- different evidence, different attacker TTPs.

### How to Obtain

Available from the SANS Institute as part of the FOR508 course supplemental materials.
The evidence was downloaded during the hackathon development period for testing.

### Evidence Artifacts Available

| Artifact | Status | Tool |
|---|---|---|
| NTFS filesystem | Mounted via ntfs-3g | fs.stat_hash, mft.timeline |
| Windows Event Logs | Parsed via evtx_dump | evtx.query |
| Memory image | Analyzed via Volatility3 | mem.pslist, mem.netscan, mem.malfind |
| Registry hives | RECmd not available on test system | registry.run_keys |
| Prefetch files | PECmd not available on test system | prefetch.run_record |

**Note on missing tools**: On the test system (WSL2 Ubuntu), Eric Zimmerman tools
(MFTECmd, PECmd, RECmd) are not available. COUNSEL degrades gracefully:
`mft.timeline` falls back to a filesystem timestamp scan (`parse_quality=0.5`),
which still contributes as an independent corroboration group. On SIFT Workstation
with Protocol SIFT installed, all tools would be available.

### What COUNSEL Found (Real Evidence Run)

See `docs/accuracy-report.md` for the full SRL-2018 run results.

---

## Evidence Handling

All evidence images are handled as follows:
1. SHA256 hash computed before investigation begins (genesis ledger entry)
2. Evidence mounted read-only at OS level
3. SHA256 hash recomputed after agent exit (Verifier process)
4. hash_in == hash_out is verified and signed in the manifest

No evidence files are modified, uploaded, or transmitted as part of COUNSEL's operation.
