# ADR-0004: Write every step to a signed, tamper-evident ledger

**Status:** Accepted
**Date:** 2026-06-11

**In one line:** every step the agent takes is recorded so that anyone can check the work and catch tampering.

A verdict is only useful if a sceptic can check it. The agent simply saying "here are my findings" gives a reviewer nothing. There is no proof the output was not edited afterward, and no way to follow a finding back to the exact tool run that produced it. For a tool whose whole pitch is "an analyst could sign this," that is a dealbreaker.

So COUNSEL writes every step to a ledger as it goes: each tool run, each change of a finding's status, the final halt. Each entry carries a fingerprint (a hash) of the entry before it, so if anyone edits one row, every row after it stops matching and the tampering shows. A separate verifier signs the whole chain with a private key, and that key never lives with the agent, so the agent cannot quietly approve its own work. The evidence is also fingerprinted before and after the run; if the two match, the analysis changed nothing.

The result is that every finding links straight to the tool runs behind it. You can click a finding and land on the exact step that produced it.

The cost is more moving parts: a key to manage, a verifier to run, and the discipline of logging everything in order. We accept it because this is the line between "an AI said so" and "here is the signed record, check it yourself."
