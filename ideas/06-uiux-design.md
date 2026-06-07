# 06 - COUNSEL UI/UX Design (deep)

Terminal-first hero (the demo) + a static, offline HTML "Case File" (the artifact judges click).
No web server. ASCII-only. Pairs with 05 (tech) and 07 (eval).

## 1. Design philosophy
- **Trust through transparency.** A forensic tool earns trust by showing its work; never present a
  conclusion without its evidence one click away.
- **Dual audience, one interface.** A junior analyst learns; a senior verifies. Progressive
  disclosure serves both from the same screen.
- **Honesty is a visual feature.** Unresolved and Contradicted claims are first-class, not hidden.
- **Match the real world.** The courtroom/case-file mental model maps to states everyone groks.

### Nielsen heuristics, applied concretely
- Visibility of status: persistent header shows current autonomous action + iteration + budget.
- Recognition over recall: claim-state legend + icons always on screen; no memorized codes.
- Error prevention: read-only by construction; nothing in the UI can mutate evidence.
- Aesthetic + minimalist: overview first; raw hex/strings behind an explicit expand.
- Help users recognize/recover: every claim shows WHY and what would change its state.

## 2. Information architecture
```
COUNSEL
  |- Case Overview      (landing: verdict-at-a-glance)
  |- Attack Timeline    (corroborated super-timeline, 3 sources)
  |- Claim Court        (the corroboration graph - the hero view)
  |- Evidence Ledger    (append-only audit log + replay)
  '- Training Mode      (toggle overlay: senior-analyst narration)
```
Global elements on every view: status header, claim-state legend, search/filter, source filters
(disk/memory/network), Training-Mode toggle.

## 3. Visual design system
Dark, evidence-room aesthetic; calm, high-contrast, low-chroma except for state signals.

### 3.1 Claim-state tokens (color + icon + text, never color alone)
```
Observed     [eye]    slate/grey   "seen in one artifact"
Corroborated [check2] teal/green   "independent evidence agrees"
Inference    [~]      amber        "plausible, incomplete support"
Contradicted [x2]     red          "conflicting evidence"
Unresolved   [?]      muted blue   "insufficient evidence"
```
Each token always renders icon + label so it is legible in grayscale and to color-blind users.

### 3.2 Type scale & spacing
```
Display 28 / Title 20 / Section 16 / Body 14 / Mono 13 (evidence) / Caption 12
8px spacing grid; max content width ~960px for report readability; monospace for all evidence
fields (paths, hashes, offsets) so they are scannable.
```
### 3.3 Core components
Claim Card, Evidence Exhibit row, Confidence meter (segmented, shows support vs contradiction),
State badge, Source chip (disk/mem/net), Timeline event, Ledger row (expandable), "Why this
matters" callout, Replay button.

## 4. The four views (wireframes)

### 4.1 Case Overview - verdict at a glance
```
+--------------------------------------------------------------------------+
| COUNSEL  Case: Stolen-Szechuan   Status: COMPLETE   Time-to-triage 6m12s |
| [eye 3] [check2 9] [~ 4] [x2 1] [? 2]            Evidence integrity: OK   |
+--------------------------------------------------------------------------+
| EXECUTIVE NARRATIVE (structured, not a log)                              |
|  Initial access via [phish doc] -> persistence [Run key] -> exec         |
|  [evil.exe] -> C2 [185.x:443] -> ... each phrase links to its claim.     |
+--------------------------------------------------------------------------+
| TOP CLAIMS                          | ATT&CK COVERAGE                     |
|  check2 payload_executed   0.93     |  T1547.001 Persistence  [corrob]    |
|  check2 c2_channel         0.88     |  T1059 Execution        [corrob]    |
|  ~      data_staged        0.41     |  T1071 C2               [corrob]    |
|  x2     ransomware_present  conflict|  ...                                |
+--------------------------------------------------------------------------+
```

### 4.2 Attack Timeline - corroborated super-timeline
```
| time      event                         sources           state         |
| 22:31  phishing doc opened              [disk][evtx]      corrob         |
| 22:33  Run key written                  [disk]            observed       |
| 22:41  evil.exe executed   x3           [disk][disk]*     corrob         |
|        (*Prefetch + Amcache independent)                                 |
| 22:42  outbound 185.x.x.x:443           [net][mem]        corrob         |
Filters: [disk][memory][network]  [confirmed only]  [inferred]  [contradicted]
Hover an event -> mini claim card; click -> jumps to Claim Court node.
```

### 4.3 Claim Court - the corroboration graph (HERO view)
```
+--------- payload_executed = CORROBORATED  support 0.93  contra 0.00 ------+
|                                                                          |
|   [registry Run key]--configures-->( evil.exe )<--executed--[Prefetch x3]|
|                                         ^                      |indep     |
|                                         +-----------------[Amcache entry] |
|   modifier: signed=false (suspicion)                                     |
|                                                                          |
|  confidence  |##########  0.93|     state history: ~ Inference (it 3)     |
|                                     -> check2 Corroborated (it 4)         |
|  WHY THIS MATTERS  A Run key proves SETUP only; Prefetch and Amcache     |
|  independently prove it RAN. [expand raw evidence] [replay] [open ledger]|
+--------------------------------------------------------------------------+
```
Interaction: nodes = entities/artifacts; edges typed (configures/executed/active/contradicts);
selecting a claim highlights its supporting (green) and contradicting (red) edges; the state-
history strip animates the self-correction (Inference -> Corroborated) - this is the moment that
wins the tiebreaker, made visible.

### 4.4 Evidence Ledger - court-grade audit
```
| seq  tool                 artifact                       hash     replay  |
| 41   registry.run_keys    .../Run                        ab3f..   [>]     |
| 42   prefetch.run_record  EVIL.EXE-1A2B.pf  off 12480     9d1c..   [>]     |
| 43   amcache.lookup       Amcache.hve                     7f02..   [>]     |
Click row -> args, raw_output_sha256, tokens, prev_hash/entry_hash, linked claim.
[>] replay re-runs the exact tool call and shows hash MATCH/MISMATCH.
Footer: chain head 7f02.. | manifest signature VALID (Ed25519, external key) | img hash in==out.
```

## 5. TUI (terminal-first hero - this is what the demo records)
`rich`/Textual layout, three regions, live:
```
+-- COUNSEL  iter 4/20  budget 38%  evidence: read-only ---------------------+
| REASONING (streaming)                | CLAIMS (live)                       |
|  > hypothesis: Run-key persistence   |  check2 persistence_configured 0.95 |
|  > need independent exec evidence;   |  ~      payload_executed       0.50  |
|    Prefetch is highest-weight indep  |  ?      payload_active         --    |
|  > calling prefetch.run_record       |                                     |
|  > Amcache agrees (independent)      | STATE CHANGE:                       |
|  > payload_executed ~ -> corroborated|  payload_executed ~ -> check2 (it4) |
+--------------------------------------+-------------------------------------+
| LEDGER  seq42 prefetch 9d1c..  seq43 amcache 7f02..   [replay] [export]    |
+---------------------------------------------------------------------------+
```
The streaming left pane is the senior-analyst narration; the right pane shows states flipping in
real time. The STATE CHANGE banner is the on-camera self-correction.

## 6. Analyst Training Mode (serves SANS's mission)
A toggle overlay that, per claim, expands four senior-analyst beats:
```
TOOL CHOSEN : prefetch.run_record - "highest-weight independent proof of execution"
EXPECTED    : "if evil.exe ran, a Prefetch record with run_count >= 1 should exist"
FOUND       : "run_count 3, last_run 22:41 - matches the persistence write at 22:33"
REVISED     : "raised payload_executed from Inference to Corroborated"
```
Plain-language "Why this matters" on every claim; hover any jargon term (MFT, Amcache, Prefetch)
for a one-line definition. This is the educational-value differentiator.

## 7. Accessibility (explicit, testable)
- All state encoded by icon + text, never color alone; WCAG AA contrast (>=4.5:1 body).
- Full keyboard navigation (tab order, j/k between claims, / to search, r to replay).
- Semantic HTML in the Case File (headings, lists, table scopes) for screen readers.
- No motion-essential info; the self-correction animation has a static state-history fallback.
- Monospace + generous spacing for hashes/paths to reduce transcription error.

## 8. Report generation pipeline (offline, no server)
`report/` consumes the signed ledger + claim graph and emits:
- a single self-contained `case_file.html` (inlined CSS/JS, opens from disk, no network), and
- a Markdown report for the repo.
Determinism: same ledger -> same report (byte-stable), so the HTML is itself auditable. Every
clickable citation resolves to a ledger seq, keeping the UI and the audit trail in lockstep.
```
```
