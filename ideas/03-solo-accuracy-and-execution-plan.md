# 03 - Solo Accuracy & Execution Plan (strictly solo)

Goal: push IR Accuracy (Criterion 2) and Breadth/Depth (Criterion 3) - your two structural
ceilings - as high as a solo, new-to-DFIR builder can, by BORROWING documented expertise instead
of relying on personal intuition. ASCII-only.

## Principle: your accuracy comes from documents, not your gut
Every corroboration rule and every weighting must trace to an authoritative source. When a judge
(FBI examiner, Mandiant) checks your tradecraft, it should resolve to a citation, not an opinion.

## Step 1 - Pick ONE ground-truth case with a FULL published solution
You need a case that (a) has disk + memory + network so the cross-source corroboration story is
real, and (b) has a detailed public walkthrough that acts as your answer key.

Candidates (verify availability + license before committing):
- **DFIR Madness - "The Stolen Szechuan Sauce"** (dfirmadness.com). Strong first choice: a
  realistic intrusion with disk image(s), memory, AND pcap, plus a complete step-by-step solution.
  Cross-source corroboration is literally the shape of the case = perfect for COUNSEL.
- **CyberDefenders.org** DFIR labs - many include official walkthroughs / answer keys.
- **Ali Hadi (ashemery.com) DFIR challenges** - documented solutions.
- **digitalcorpora.org / NIST CFReDS** scenarios - documented, license-friendly.

Plus: run it ALSO on the hackathon's provided SIFT sample data (judges may test against theirs).
Document BOTH datasets in the Dataset Documentation deliverable.

ACTION: confirm the case is downloadable, its license permits this use, and the walkthrough is
detailed enough to serve as ground truth. (I can web-verify this for you on request.)

## Step 2 - Encode tradecraft PROVENANCE into every rule
Each rule's evidentiary weights cite a source. Examples of the authorities to lean on:
- SANS DFIR posters (the "Find Evil" / Windows Forensic Analysis / Hunt Evil posters).
- SANS FOR500 / FOR508 course concepts (publicly summarized in many writeups).
- Eric Zimmerman tool docs (PECmd/AmcacheParser/RECmd) for what each artifact means.
- Volatility documentation for memory plugin semantics.
Store provenance as a field in the rule schema: `evidence_weight + source_citation`. This is what
makes your accuracy DEFENSIBLE rather than just asserted.

## Step 3 - Build a rule-validation harness (turn your dev strength into accuracy)
This is the move that converts "I'm new to DFIR" into a non-issue:
- For each rule, write a test that runs it against the ground-truth case and asserts it produces
  the finding the published solution documents (right artifact, right offset, right claim state).
- Track: true positives, false positives, missed artifacts (false negatives), caught
  hallucinations. This IS your Accuracy Report - generated, not hand-waved.
- A rule that disagrees with the answer key is a bug you fix BEFORE submission. The answer key,
  not you, is the source of truth.

## Step 4 - One external sanity check
Post your finished rule set in the Protocol SIFT Slack and ask one IR practitioner to review it
once. A single expert pass catches the naive weighting mistakes that would cost Criterion 2. This
is allowed (it's feedback, not co-authorship) and is the cheapest accuracy insurance you have.

## Step 5 - Depth: one incident, three sources, fully reconstructed
To max Criterion 3 solo, do NOT spread thin. Take the one case and reconstruct the FULL kill
chain with cross-source corroboration:
- disk (registry/prefetch/amcache/MFT) + memory (pslist/netscan/malfind) + network (pcap via
  zeek/tshark). A claim like payload_active becomes strongly corroborated when the disk persistence,
  the live memory process, AND the C2 connection in the pcap all line up.
This is the "depth beats breadth" win the brief explicitly rewards.

## Adjusted solo build order (within the 13-day plan in 02-counsel.md)
1. MVP loop on DISK only: 4 tools (registry, prefetch, amcache, hash) + 5 rules + ledger +
   self-correction + bypass test. Validate against the answer key.
2. Add MEMORY (pslist/netscan) -> unlocks payload_active + the strongest corroboration.
3. Add NETWORK (pcap) -> three-source corroboration for the depth criterion.
4. Only then: timeline, yara, more rules.
Never cut: read-only/no-shell, externally-signed ledger, the benchmark/validation harness, the
on-camera self-correction.

## Honest ceiling, restated
With this plan, realistic outcome moves to roughly:
Accuracy 7-8 (up from 6-7), Depth 7-8 (up from 6-7), with Constraint and Audit Trail at 8-9.
That is a legitimate top-tier, could-win-a-prize solo submission. It is NOT a guaranteed straight
10 on every criterion - that remains gated by being solo and new to DFIR, which no plan removes.
The bet you are making: architecture + audit rigor + documented honesty outweigh a team's raw
domain depth, for THIS judge panel. That bet is winnable.
