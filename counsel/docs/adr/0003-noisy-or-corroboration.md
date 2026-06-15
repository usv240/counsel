# ADR-0003: Noisy-OR corroboration and the five-state claim model

**Status:** Accepted
**Date:** 2026-06-11

---

Once the engine owns the verdict (ADR-0001), it needs a rule for *how* it decides. The naive option is to attach a confidence number to each finding - but a confidence score is only as trustworthy as whatever produced it, and if that is the LLM, we are back to a vibe dressed up as a number. The engine needs a confidence model grounded in the evidence itself.

The decision has two parts.

**Noisy-OR over independent evidence groups.** Each corroboration rule lists signals, and every signal belongs to an independence group (a registry hive, a memory image, a network capture). Support combines as `1 - PRODUCT(1 - effective_weight)` across groups, and a claim only reaches CORROBORATED when **two or more independent groups** agree *and* combined support is at least 0.80. The independence requirement is the important part: two readings of the same artifact are not corroboration. The C2 finding in the demo is CORROBORATED only because a memory socket table and a separate network flow record - two acquisition methods - both show the same external address.

**Five states, not a boolean.** A claim moves through OBSERVED -> INFERENCE -> and then to one of CORROBORATED, CONTRADICTED, or UNRESOLVED. The two that most tools lack are CONTRADICTED (an independent higher-weight signal actively refutes the claim - this is what flips `lateral_movement` on screen) and UNRESOLVED (the bounded search finished without enough independent support, so the engine declines to assert rather than guess). "I don't know" is a valid forensic answer, and making it a first-class state is what lets recall stay at 1.0 while the false-positive rate drops to 0.0.

The trade-off is that someone has to model the weights and independence groups per rule, and getting them wrong skews results. We mitigate that by sourcing weights from forensic practice (SANS FOR500/FOR508, MITRE ATT&CK) and pinning the whole rule set's hash in the signed ledger, so the exact scoring logic behind any verdict is auditable after the fact.
