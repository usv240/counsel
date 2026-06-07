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

The locked answer key for COUNSEL's accuracy benchmark is in:
`bench/answer_key_szechuan_sauce.json`

It was locked on 2026-06-07T00:00:00Z before running COUNSEL on the case.
This prevents post-hoc rationalization of the benchmark results.

**True Positives (expected CORROBORATED claims)**:
- persistence_configured - Run key in HKCU
- payload_present - Malicious svchost.exe in AppData/Local/Temp
- payload_executed - Confirmed by Prefetch + Amcache (independent)
- payload_active - Process in memory (if memory image available)
- c2_communication - External IP in memory + PCAP
- exfiltration - Data egress over C2 channel

**True Negatives (should NOT be CORROBORATED)**:
- lateral_movement - Single workstation; no lateral movement evidence
- credential_access - No credential dumping evidence

### Privacy and Legal

This is a publicly released forensic training case. The data is synthetic/fictional
(there is no real "Rick" or real Szechuan sauce company). Safe to use for research.

---

## Secondary Case: [TBD - Generality Proof]

A second forensic case will be added to demonstrate COUNSEL generalizes beyond
the Szechuan Sauce image. Candidates:
- DFIR.training other challenges
- MagnetForensics CTF cases (publicly released)
- Volatility Foundation memory samples

The secondary case is used for generality - we run COUNSEL on it without an answer key
and show the corroboration engine adapts to new TTPs without rule changes.

---

## Evidence Handling

All evidence images are handled as follows:
1. SHA256 hash computed before investigation begins (genesis ledger entry)
2. Evidence mounted read-only at OS level
3. SHA256 hash recomputed after agent exit (Verifier process)
4. hash_in == hash_out is verified and signed in the manifest

No evidence files are modified, uploaded, or transmitted as part of COUNSEL's operation.
