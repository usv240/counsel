# Architecture Decision Records

The big decisions behind COUNSEL, and why we made them. Each one is short: the
problem, what we did, and the honest trade-off.

| # | Decision |
|---|----------|
| [0001](0001-engine-owns-the-verdict.md) | The engine decides the verdict, not the AI |
| [0002](0002-typed-mcp-server-not-shell.md) | Give the agent typed tools, not a shell |
| [0003](0003-noisy-or-corroboration.md) | Confirm a finding only when two independent sources agree |
| [0004](0004-signed-hash-chained-ledger.md) | Write every step to a signed, tamper-evident ledger |
| [0005](0005-parse-before-return.md) | Clean the evidence into typed fields before the model sees it |

For the full picture, see the [architecture walkthrough](../architecture.md).
