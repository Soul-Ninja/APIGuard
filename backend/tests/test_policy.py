import pytest
from apiguard.engine.policy import PolicyEvaluator
from apiguard.engine.models import Rule, RuleType, PolicyResult

def test_policy_ternary_results():
    rule = Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project")

    # Owner access -> ALLOW
    assert PolicyEvaluator.evaluate(rule, "usr_alice", "usr_alice") == PolicyResult.ALLOW

    # Non-owner access -> DENY
    assert PolicyEvaluator.evaluate(rule, "usr_bob", "usr_alice") == PolicyResult.DENY

    # Missing ownership context -> UNKNOWN
    assert PolicyEvaluator.evaluate(rule, "usr_bob", None) == PolicyResult.UNKNOWN

    # No rule at all -> UNKNOWN
    assert PolicyEvaluator.evaluate(None, "usr_bob", "usr_alice") == PolicyResult.UNKNOWN

def test_admin_and_support_exceptions():
    rule = Rule(rule_type=RuleType.OWNER_ONLY, resource_type="Project")

    # Admin override -> ALLOW
    assert PolicyEvaluator.evaluate(rule, "usr_admin", "usr_alice", caller_role="admin") == PolicyResult.ALLOW

    # Support override -> ALLOW
    assert PolicyEvaluator.evaluate(rule, "usr_support", "usr_alice", caller_role="support") == PolicyResult.ALLOW
