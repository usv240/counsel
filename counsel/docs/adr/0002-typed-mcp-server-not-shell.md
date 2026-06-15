# ADR-0002: A typed MCP server, not shell access

**Status:** Accepted
**Date:** 2026-06-10

---

The fastest way to give an agent forensic capability is a single `execute_shell` tool. Point it at a SIFT workstation and let it run `reg`, `vol.py`, `PECmd`, `tshark`, whatever it decides it needs. It is powerful and it is a trap. A shell tool can also delete files, write to the evidence mount, and exfiltrate - and the only thing standing between the agent and a destroyed chain of custody is a prompt asking it nicely not to. In DFIR, modifying the original evidence (spoliation) makes findings inadmissible. "We told the model the mount was read-only" is not a defense a forensic examiner can stand behind.

The alternative considered was shell access plus a read-only mount plus prompt-level restrictions. The read-only mount helps, but it is one layer, and it does nothing about the agent running an expensive or destructive command against a remote endpoint, or about a 50-megabyte raw tool dump blowing out the context window.

The decision: build a purpose-built MCP server that exposes **typed forensic functions** - `registry.run_keys`, `mft.timeline`, `amcache.lookup`, `mem.malfind`, and so on, eleven of them - instead of a generic command runner. The agent physically cannot run a destructive command, because the server does not expose one. This is capability isolation: the boundary is enforced by what the server *can do*, not by what the model is *told* to do. The server also parses each tool's raw output into typed records before returning them (see ADR-0005), so the model never receives a giant text blob and never sees attacker-controlled bytes as free text.

The honest cost is effort. This is, as the hackathon's own rules note, "the most sound architecture in the evaluation - and the most work." Every artifact family needs a typed wrapper and a parser. But the result is zero-spoliation-by-construction and a clean, bounded interface, and it makes the three trust boundaries in the README real rather than aspirational.
