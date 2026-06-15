# ADR-0002: Give the agent typed tools, not a shell

**Status:** Accepted
**Date:** 2026-06-10

**In one line:** the agent can only call a fixed set of safe, typed forensic functions, so it physically cannot damage the evidence.

The easy way to give an agent forensic power is one `run_command` tool and a shell. It works, and it is a trap. A shell can also delete files, write to the evidence, and leak data. The only thing stopping it is a prompt asking it not to. In forensics, changing the original evidence at all makes your findings useless in court. "We told the model the drive was read-only" is not something an examiner can stand behind.

So instead of a shell, COUNSEL exposes eleven specific functions: read the run keys, build the file timeline, look up amcache, scan memory for injection, and so on. The agent cannot run a destructive command because no such command exists in its toolbox. The limit is built into what the server offers, not into what the model is told.

Each function also cleans up the raw tool output and turns it into plain, typed records before the model ever sees it ([ADR-0005](0005-parse-before-return.md)). That keeps huge text dumps out of the model's context and keeps attacker-controlled bytes from being read as instructions.

The honest cost: this is the most work of any approach. Every artifact type needs its own wrapper and parser. We chose it because it makes the safety real. The evidence cannot be harmed by construction, not by good behavior.
