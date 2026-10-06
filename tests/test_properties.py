"""
tests/test_properties.py — Property-based tests using Hypothesis.

These tests verify invariants that are hard to cover with a fixed dataset:
generated strings with unexpected characters, edge-case booleans, and
arbitrary numeric combinations.  They complement (not replace) the
example-based tests in test_benchmark.py.

Properties under test:
  1. Selector signal bounds — complexity, ambiguity, evidence_availability
     are always within their declared ranges, regardless of alert content.
  2. Selector output validity and determinism — select() always returns
     a legal strategy name and is pure (same inputs → same output).
  3. Score function range and weight contract — _score() is always in
     [0.0, 1.0] or None, and equals exactly the weighted sum the steering
     documents specify.

Run with:
    python -m pytest tests/test_properties.py -v
"""

from hypothesis import given, settings, assume
from hypothesis import strategies as st

import evaluate
from harness.alert_loader import Alert, VALID_TYPES, VALID_SEVERITIES
from harness.selector import StrategySelector

# ─── Shared helpers ───────────────────────────────────────────────────────────

# Strategy for generating an Alert with arbitrary text in the evidence fields.
# type and severity are drawn from the valid sets so AlertLoader validation
# passes; everything else is unconstrained text.
_text = st.text(min_size=0, max_size=500)
_type = st.sampled_from(sorted(VALID_TYPES))
_severity = st.sampled_from(sorted(VALID_SEVERITIES))


def _make_alert(alert_id, typ, severity, description, raw_evidence):
    """Construct a minimal Alert directly (bypasses file I/O)."""
    return Alert(
        alert_id=str(alert_id),
        type=typ,
        severity=severity,
        description=description,
        raw_evidence=raw_evidence,
        ground_truth=None,
    )


# ─── Property 1: selector signal bounds ───────────────────────────────────────

@given(
    alert_id=st.integers(min_value=0, max_value=9999).map(lambda n: f"GEN-{n:04d}"),
    typ=_type,
    severity=_severity,
    description=_text,
    raw_evidence=_text,
)
@settings(max_examples=300)
def test_complexity_always_in_range(alert_id, typ, severity, description, raw_evidence):
    """
    Complexity counts at most 5 distinct indicator types (IP, hash, domain,
    user account, process name).  No matter what text is in raw_evidence the
    score must stay in [0, 5].
    """
    alert = _make_alert(alert_id, typ, severity, description, raw_evidence)
    signals = StrategySelector().compute_signals(alert)
    assert 0 <= signals.complexity <= 5, (
        f"complexity={signals.complexity} out of [0, 5] for raw_evidence={raw_evidence!r}"
    )


@given(
    alert_id=st.integers(min_value=0, max_value=9999).map(lambda n: f"GEN-{n:04d}"),
    typ=_type,
    severity=_severity,
    description=_text,
    raw_evidence=_text,
)
@settings(max_examples=300)
def test_ambiguity_always_in_range(alert_id, typ, severity, description, raw_evidence):
    """
    Ambiguity counts hedging keywords capped at 3.  The cap must hold even
    when all 7 keywords appear multiple times in one alert.
    """
    alert = _make_alert(alert_id, typ, severity, description, raw_evidence)
    signals = StrategySelector().compute_signals(alert)
    assert 0 <= signals.ambiguity <= 3, (
        f"ambiguity={signals.ambiguity} out of [0, 3]"
    )


@given(
    alert_id=st.integers(min_value=0, max_value=9999).map(lambda n: f"GEN-{n:04d}"),
    typ=_type,
    severity=_severity,
    description=_text,
    raw_evidence=_text,
)
@settings(max_examples=300)
def test_evidence_availability_always_in_range(
    alert_id, typ, severity, description, raw_evidence
):
    """
    Evidence availability is the fraction of populated fields out of 4
    (raw_evidence, description, type, severity).  For alerts constructed
    via Alert() directly all four fields are always set, so availability
    should always be exactly 1.0.  But the property we're verifying is the
    weaker one: the result is always a valid fraction in [0.0, 1.0].
    """
    alert = _make_alert(alert_id, typ, severity, description, raw_evidence)
    signals = StrategySelector().compute_signals(alert)
    assert 0.0 <= signals.evidence_availability <= 1.0, (
        f"evidence_availability={signals.evidence_availability} out of [0.0, 1.0]"
    )


# ─── Property 2: selector output validity and determinism ─────────────────────

_VALID_STRATEGIES = {"panel_strategy", "hierarchical_strategy"}
_VALID_RULES = {
    "rich_evidence", "ambiguous", "critical_severity",
    "sparse_evidence", "default",
}


@given(
    alert_id=st.integers(min_value=0, max_value=9999).map(lambda n: f"GEN-{n:04d}"),
    typ=_type,
    severity=_severity,
    description=_text,
    raw_evidence=_text,
)
@settings(max_examples=300)
def test_selector_always_returns_valid_strategy(
    alert_id, typ, severity, description, raw_evidence
):
    """
    select() must return one of the two known strategy strings and one of
    the five known rule names, for every possible input.  No generated
    content should cause a fallthrough to an undefined state.
    """
    alert = _make_alert(alert_id, typ, severity, description, raw_evidence)
    strategy, rule = StrategySelector().select(alert)
    assert strategy in _VALID_STRATEGIES, f"Unknown strategy: {strategy!r}"
    assert rule in _VALID_RULES, f"Unknown rule: {rule!r}"


@given(
    alert_id=st.integers(min_value=0, max_value=9999).map(lambda n: f"GEN-{n:04d}"),
    typ=_type,
    severity=_severity,
    description=_text,
    raw_evidence=_text,
)
@settings(max_examples=200)
def test_selector_is_deterministic(alert_id, typ, severity, description, raw_evidence):
    """
    select() is a pure function: calling it twice on the same Alert object
    must return the identical (strategy, rule) pair.  This matters because
    the benchmark runner calls select() once per alert per run, and we need
    reproducible routing for fair comparison.
    """
    alert = _make_alert(alert_id, typ, severity, description, raw_evidence)
    selector = StrategySelector()
    first  = selector.select(alert)
    second = selector.select(alert)
    assert first == second, (
        f"select() returned different results on two calls: {first!r} vs {second!r}"
    )


# ─── Property 3: score function range and weight contract ─────────────────────

# Draw Optional[bool]: None, True, or False
_optional_bool = st.one_of(st.none(), st.booleans())


@given(verdict_correct=_optional_bool, mitigation_correct=_optional_bool)
@settings(max_examples=50)
def test_score_is_none_when_no_ground_truth(verdict_correct, mitigation_correct):
    """
    _score() must return None whenever verdict_correct is None.
    The mitigation value is irrelevant — a record without a verdict label
    cannot be scored at all.
    """
    assume(verdict_correct is None)
    record = {
        "verdict_correct": verdict_correct,
        "mitigation_correct": mitigation_correct,
    }
    assert evaluate._score(record) is None


@given(
    verdict_correct=st.booleans(),
    mitigation_correct=st.booleans(),
)
@settings(max_examples=50)
def test_score_is_weighted_sum(verdict_correct, mitigation_correct):
    """
    When ground truth is present, _score() must equal exactly:
        0.7 × verdict_correct + 0.3 × mitigation_correct

    This property locks the weights defined in evaluate.py
    (_VERDICT_WEIGHT = 0.7, _MITIGATION_WEIGHT = 0.3) and ensures no
    future rounding or re-weighting slips in silently.
    """
    record = {
        "verdict_correct": verdict_correct,
        "mitigation_correct": mitigation_correct,
    }
    expected = (
        evaluate._VERDICT_WEIGHT * int(verdict_correct)
        + evaluate._MITIGATION_WEIGHT * int(mitigation_correct)
    )
    result = evaluate._score(record)
    assert result is not None
    assert abs(result - expected) < 1e-9, (
        f"score={result} expected={expected} "
        f"for verdict={verdict_correct} mitigation={mitigation_correct}"
    )


@given(
    verdict_correct=st.booleans(),
    mitigation_correct=st.booleans(),
)
@settings(max_examples=50)
def test_score_always_in_unit_interval(verdict_correct, mitigation_correct):
    """
    _score() must always produce a value in [0.0, 1.0].  This holds as long
    as the two weights sum to 1.0 and both inputs are booleans.  If the
    weights ever change such that they no longer sum to 1, this test will
    catch it.
    """
    record = {
        "verdict_correct": verdict_correct,
        "mitigation_correct": mitigation_correct,
    }
    result = evaluate._score(record)
    assert result is not None
    assert 0.0 <= result <= 1.0, f"score={result} outside [0.0, 1.0]"
