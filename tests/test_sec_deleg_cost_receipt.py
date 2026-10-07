"""Cost receipts must not carry negative / non-finite costs (budget refund)."""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from ampro.delegation.cost_receipt import CostReceipt


def _receipt(cost: float) -> CostReceipt:
    return CostReceipt(
        agent_id="agent://a.example.com",
        task_id="t1",
        cost_usd=cost,
        nonce="n1",
        signature="sig",
        issued_at="2026-01-01T00:00:00Z",
    )


@pytest.mark.parametrize("bad", [-0.01, -1000.0, math.nan, math.inf, -math.inf])
def test_negative_or_non_finite_cost_rejected(bad):
    with pytest.raises(ValidationError):
        _receipt(bad)


def test_zero_and_positive_cost_accepted():
    assert _receipt(0.0).cost_usd == 0.0
    assert _receipt(1.25).cost_usd == 1.25
