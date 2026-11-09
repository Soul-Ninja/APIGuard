import pytest
from apiguard.engine.confidence import compute_hypothesis_confidence, compute_edge_confidence
from apiguard.engine.models import Provenance

def test_confidence_provenance_and_bonuses():
    # Base documented
    base_doc = compute_hypothesis_confidence(Provenance.DOCUMENTED, 0, 0)
    assert base_doc == 0.85

    # Base propagated starts lower
    base_prop = compute_hypothesis_confidence(Provenance.PROPAGATED, 0, 0)
    assert base_prop == 0.50

    # Supporting observation increases confidence
    with_bonus = compute_hypothesis_confidence(Provenance.PROPAGATED, 2, 0)
    assert with_bonus == 0.70

    # Contradiction penalizes confidence
    with_penalty = compute_hypothesis_confidence(Provenance.PROPAGATED, 2, 1)
    assert with_penalty == 0.40

    # Bounds check
    assert compute_hypothesis_confidence(Provenance.DOCUMENTED, 10, 0) <= 0.98
    assert compute_hypothesis_confidence(Provenance.HEURISTIC, 0, 10) >= 0.05
