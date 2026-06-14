"""
Rate-limit pacing & context-compaction tests (RL1-RL5).

These prove, deterministically and without any API call, that COUNSEL stays under
the organisation's input-tokens-per-minute limit by design rather than relying on
429 backoff:

  RL1: a tool result with many records is capped to MAX_RECORDS_IN_CONTEXT and
       annotated with the true total (forensic completeness preserved in ledger).
  RL2: a small tool result is passed through unchanged.
  RL3: pacing does NOT sleep when the rolling 60s window is under budget.
  RL4: pacing DOES sleep when the rolling window would breach the budget.
  RL5: a completed request's usage is recorded into the pacing window.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from counsel.agent import loop as loop_module
from counsel.agent.loop import (
    CounselLoop,
    LoopConfig,
    INPUT_TPM_BUDGET,
    MAX_RECORDS_IN_CONTEXT,
)

RULES_DIR = Path(__file__).resolve().parents[1] / "counsel" / "rules"


def _loop() -> CounselLoop:
    return CounselLoop(LoopConfig(run_id="rl-test", rules_dir=RULES_DIR))


# ---------------------------------------------------------------------------
# Context compaction
# ---------------------------------------------------------------------------

def test_rl1_large_result_is_capped():
    lp = _loop()
    big = {"tool": "evtx.query", "records": [{"i": i} for i in range(50)], "parse_quality": 1.0}
    out = lp._compact_result_for_context(big)
    assert len(out["records"]) == MAX_RECORDS_IN_CONTEXT
    assert out["records_truncated"]["total"] == 50
    assert out["records_truncated"]["shown"] == MAX_RECORDS_IN_CONTEXT
    # original must not be mutated (ledger / engine keep the full set)
    assert len(big["records"]) == 50


def test_rl2_small_result_passthrough():
    lp = _loop()
    small = {"tool": "fs.stat_hash", "records": [{"i": 0}, {"i": 1}], "parse_quality": 1.0}
    out = lp._compact_result_for_context(small)
    assert out is small  # unchanged reference, no truncation key
    assert "records_truncated" not in out


# ---------------------------------------------------------------------------
# Token-budget pacing
# ---------------------------------------------------------------------------

def test_rl3_no_sleep_when_under_budget(monkeypatch):
    lp = _loop()
    slept: list[float] = []

    async def fake_sleep(d):
        slept.append(d)

    monkeypatch.setattr(loop_module.asyncio, "sleep", fake_sleep)
    # Window has a single small request well under budget.
    lp._token_window.append((time.monotonic(), 1000))
    asyncio.run(lp._pace_for_token_budget(est_tokens=1000))
    assert slept == [], "should not pace when comfortably under the per-minute budget"


def test_rl4_sleeps_when_over_budget(monkeypatch):
    lp = _loop()
    slept: list[float] = []

    async def fake_sleep(d):
        slept.append(d)
        lp._token_window.clear()  # simulate the 60s window draining after the wait

    monkeypatch.setattr(loop_module.asyncio, "sleep", fake_sleep)
    # Fill the window right up to the budget so the next request must wait.
    lp._token_window.append((time.monotonic(), INPUT_TPM_BUDGET))
    asyncio.run(lp._pace_for_token_budget(est_tokens=INPUT_TPM_BUDGET))
    assert len(slept) == 1, f"expected exactly one pacing sleep, got {slept}"
    assert slept[0] > 0


def test_rl5_usage_recorded():
    lp = _loop()

    class _Usage:
        input_tokens = 4242

    class _Resp:
        usage = _Usage()

    lp._record_token_usage(_Resp())
    assert lp._last_input_tokens == 4242
    assert sum(t for _, t in lp._token_window) == 4242
