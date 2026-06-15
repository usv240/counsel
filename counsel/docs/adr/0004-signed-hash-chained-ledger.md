# ADR-0004: A signed, hash-chained ledger for court-grade provenance

**Status:** Accepted
**Date:** 2026-06-11

---

A verdict is only as useful as a sceptic's ability to check it. Agent output on its own - "here are my findings" - gives a reviewer nothing to verify. There is no proof the output was not edited after the run, and no way to trace a specific finding back to the specific tool execution that produced it. For a tool whose entire pitch is "a senior analyst could sign this," that gap is fatal.

The decision: every step of the investigation is appended to a hash-chained ledger, and the ledger is signed. Each entry stores the SHA256 of the previous entry, so altering any row breaks every hash after it - tampering is detectable by recomputation. A separate Verifier process signs the chain with an Ed25519 key, and that key lives in the Launcher/Verifier, never in the agent (the agent cannot sign its own work - see trust boundary B2). The evidence itself is SHA256-hashed before and after the run; a match proves the analysis modified nothing. And every claim's evidence carries the ledger sequence numbers of the tool calls behind it, so any finding is one click from the exact `tool_call` that produced it.

Alternatives were thinner. A plain append-only log gives ordering but no tamper-evidence. Signing only the final report proves the report is ours but says nothing about the steps that produced it. Neither lets a judge trace a finding to its source, which is an explicit judging requirement and, more importantly, the actual standard for forensic admissibility.

The cost is operational complexity: a keypair to manage, a verifier to run, and the discipline of writing every tool call, ruling change, and halt to the chain in the correct order across process boundaries. We accept it because tamper-evidence and end-to-end traceability are exactly what move a result from "an AI said so" to "here is the signed record, verify it yourself." That is the difference the ledger buys.
