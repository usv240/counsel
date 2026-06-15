# ADR-0003: Confirm a finding only when two independent sources agree

**Status:** Accepted
**Date:** 2026-06-11

**In one line:** a finding is "confirmed" only when two independent kinds of evidence point the same way, and the engine is allowed to say "I don't know."

Once the engine owns the verdict (ADR-0001), it needs a rule for how it decides. The simplest idea is to attach a confidence number to each finding. But a number is only as honest as whatever produced it, and if that is the AI, we are back to a guess wearing a percentage. The confidence has to come from the evidence.

Here is the rule. Each piece of evidence belongs to a source group: a registry hive, a memory image, a network capture. A finding is only CONFIRMED when at least **two different source groups** agree and their combined strength clears a set bar. Two readings of the same artifact do not count - that is not corroboration, it is the same fact twice. In the demo, the command-and-control finding is confirmed only because the memory's socket table and a separate network capture both show the same outside address.

A finding also has more than two outcomes. It can be CONFIRMED, REFUTED (a stronger independent signal says the opposite, which is what flips "lateral movement" on screen), or LEFT OPEN (the search finished without enough support, so the engine declines to claim it). Letting the engine say "I don't know" is the whole point. It is how COUNSEL finds everything real while still raising zero false alarms.

The trade-off: someone has to set the weights and the source groups for each rule, and bad values would skew the results. We base them on standard forensic practice (SANS, MITRE ATT&CK) and record the exact rule set's fingerprint in the signed ledger, so anyone can audit the scoring behind a verdict later.
