"""
Confidence Model for APIGuard

IMPORTANT:
This confidence score is a deterministic heuristic scoring model based on graph provenance
and empirical observations, NOT a formal statistical probability.
"""

from typing import List
from apiguard.engine.models import Provenance

# Base confidence values based on evidence provenance
BASE_CONFIDENCE_MAP = {
    Provenance.DOCUMENTED: 0.85,
    Provenance.SCHEMA: 0.80,
    Provenance.OBSERVED: 0.75,
    Provenance.PROPAGATED: 0.50,
    Provenance.HEURISTIC: 0.35,
}

SUPPORTING_BONUS = 0.10
CONTRADICTION_PENALTY = 0.30

MIN_CONFIDENCE = 0.05
MAX_CONFIDENCE = 0.98

def compute_hypothesis_confidence(
    provenance: Provenance,
    supporting_count: int,
    contradiction_count: int
) -> float:
    """
    Computes confidence for an inferred or propagated hypothesis.
    Base score + supporting bonuses - contradiction penalties.
    """
    base = BASE_CONFIDENCE_MAP.get(provenance, 0.40)
    score = base + (supporting_count * SUPPORTING_BONUS) - (contradiction_count * CONTRADICTION_PENALTY)
    return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, score)), 2)

def compute_edge_confidence(
    provenance: Provenance,
    is_direct_param_match: bool = True
) -> float:
    """
    Computes confidence for a DAG edge linking two operations.
    """
    base = BASE_CONFIDENCE_MAP.get(provenance, 0.50)
    if not is_direct_param_match:
        base -= 0.15
    return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, base)), 2)
