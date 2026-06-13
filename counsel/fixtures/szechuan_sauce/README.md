# Szechuan Sauce - Demo Fixture Set

Pre-recorded forensic tool outputs from the "Stolen Szechuan Sauce" DFIR scenario
(Dave Cowen / SANS FOR508 public case study).

## What This Is

When `COUNSEL_FIXTURE_DIR` points to this directory, all 11 MCP forensic tools load
these JSON files instead of invoking real binaries on a SIFT Workstation.
This lets you run the full COUNSEL investigation loop - including Claude Haiku 4.5 reasoning,
Noisy-OR corroboration math, and the 5-state claim model - on any machine.

## Scenario Summary

- **Victim machine:** MORTY-PC (Windows 7)
- **User account:** Rick (local admin)
- **Incident window:** 2017-10-04 14:19 - 18:44 UTC
- **Attacker C2:** 185.220.101.47 (Tor exit node)
- **Attacker objective:** Exfiltrate the Szechuan Sauce formula

## Ground-Truth Attack Chain

1. Rick opens a malicious download; `wupd.exe` drops to `%TEMP%`
2. `wupd.exe` establishes a Meterpreter reverse TCP shell to port 4444
3. `wupd.exe` spawns `svchost32.exe` (beacon + exfil agent) and adds it to Run key
4. `cmd.exe` is spawned to copy the secret formula to `%TEMP%`
5. `svchost32.exe` exfiltrates 4.2 MB over port 8080 to the same C2 server
6. A scheduled task is created for persistence across reboots

## Fixture Files

| File | Tool | Key Signal |
|---|---|---|
| registry_run_keys.json | registry.run_keys | HKCU\\Run - wupd.exe + svchost32.exe |
| prefetch_run_record.json | prefetch.run_record | wupd.exe ran 7x; svchost32.exe 3x |
| amcache_lookup.json | amcache.lookup | Both executables in Amcache (no company, no sig) |
| fs_stat_hash.json | fs.stat_hash | wupd.exe present, unsigned, SHA256 recorded |
| mft_timeline.json | mft.timeline | File creation at incident time; sauce doc deleted |
| yara_scan.json | yara.scan | Meterpreter_Reverse_TCP rule fires on wupd.exe |
| mem_pslist.json | mem.pslist | wupd.exe (PID 2104) + svchost32.exe (PID 2388) active |
| mem_netscan.json | mem.netscan | Active ESTABLISHED connections to 185.220.101.47 |
| mem_malfind.json | mem.malfind | PAGE_EXECUTE_READWRITE in wupd.exe + injected region in explorer.exe |
| net_flows.json | net.flows | 4.2 MB exfil over port 8080 to C2 IP |
| evtx_query.json | evtx.query | EID 4688 process create + EID 4663 file access on sauce doc |

## Running the Demo

```bash
export COUNSEL_FIXTURE_DIR="$(pwd)/counsel/fixtures/szechuan_sauce"
counsel investigate "Investigate for malware persistence and data exfiltration on MORTY-PC"
```

On Windows:
```powershell
$env:COUNSEL_FIXTURE_DIR = "counsel\fixtures\szechuan_sauce"
counsel investigate "Investigate for malware persistence and data exfiltration on MORTY-PC"
```

Expected COUNSEL output: CORROBORATED claims for persistence_configured, payload_executed,
payload_present, payload_active, and C2_communication with confidence >= 0.80 across
at least 3 independent artifact groups.
