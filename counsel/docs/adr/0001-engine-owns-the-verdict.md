# ADR-0001: The corroboration engine, not the language model, owns every verdict

**Status:** Accepted
**Date:** 2026-06-10

---

The obvious way to build an AI DFIR agent is to hand the model the evidence and ask "what does this show?" It works in a demo. It also hallucinates. An LLM that sees an authentication event in an EVTX log will happily report "lateral movement: confirmed," because the words are there. It cannot tell the difference between "the string lsass appears" and "lsass was injected." In incident response that distinction is the whole job, and a confident-but-wrong finding is worse than no finding - it launders a guess into an authoritative claim that ends up in a report, or in court.

Three softer fixes were considered and rejected. **Better prompting** ("only assert a finding if two independent sources agree") is a prompt-based guardrail: it holds until the model ignores it, and the adversarial-injection test (see ADR-0005) shows attackers can plant text in the evidence that tells the model to ignore exactly such instructions. **A fact-checker pass** is just another LLM call with the same anchoring problem. **Ensemble voting** averages over noise, not over genuine independent evidence.

The decision: the language model never assigns a claim's state. It is a router - it decides *which forensic tool to run next* and reasons about what is still missing. A separate, deterministic corroboration engine reads the typed records those tools return and assigns each claim one of five states (see ADR-0003). The model's output is an input to the engine, never the verdict itself.

This is the architectural core of COUNSEL, and it is what the line "the AI decides where to look, the math decides what is true" actually means. The trade-off is real: the engine needs rules, expressed in a YAML corroboration DSL, which is more upfront work than writing a prompt. But the payoff is a verdict that is reproducible (the same evidence always yields the same ruling), measurable (false-positive rate 1.0 -> 0.0 against a naive baseline), and defensible (every ruling traces to typed evidence, not to a sentence the model generated). A prompt cannot give you any of those three.
