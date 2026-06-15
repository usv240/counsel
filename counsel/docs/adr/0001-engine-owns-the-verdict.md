# ADR-0001: The engine decides the verdict, not the AI

**Status:** Accepted
**Date:** 2026-06-10

**In one line:** the AI chooses what to investigate; a fixed set of rules decides what is actually true.

If you hand evidence to an AI and ask "what happened here?", it will make things up. It sees the word "lsass" in a log and reports "credentials were stolen" even when nothing was. In a real case that kind of confident guess is dangerous, because it can end up in an incident report or a courtroom.

So in COUNSEL the AI never decides a finding. It only decides the next step: which forensic tool to run. A separate engine reads the evidence those tools return and gives each finding a status. The AI investigates. The engine rules.

Why not just tell the AI to be careful in its prompt? Because a rule written in a prompt only holds until the model ignores it, and our injection test ([ADR-0005](0005-parse-before-return.md)) shows an attacker can plant text in the evidence that tells the model to do exactly that. A rule built into the code cannot be talked out of.

The cost is that the engine needs rules written ahead of time, in a simple YAML format. That is more work than writing a prompt. In return you get three things a prompt can never give you: the same evidence always produces the same verdict, the false-positive rate drops from 1.0 to 0.0 against a plain LLM, and every finding traces back to real evidence instead of a sentence the model wrote.
