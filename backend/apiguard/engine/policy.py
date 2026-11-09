from typing import Optional
from apiguard.engine.models import Rule, RuleType, PolicyResult

class PolicyEvaluator:
    """
    Evaluates authorization rules to ternary results: allow, deny, or unknown.
    Evidence before conclusions: missing or uncertain rules ALWAYS return UNKNOWN, never vulnerable.
    """
    @staticmethod
    def evaluate(
        rule: Optional[Rule],
        caller_identity_id: str,
        resource_owner_identity_id: Optional[str],
        caller_role: Optional[str] = None
    ) -> PolicyResult:
        if rule is None:
            return PolicyResult.UNKNOWN

        # Admin override exception
        if caller_role == "admin":
            return PolicyResult.ALLOW

        # Support read-only override exception
        if caller_role == "support" and rule.rule_type in {RuleType.OWNER_ONLY, RuleType.AUTH_REQUIRED}:
            return PolicyResult.ALLOW

        if rule.rule_type == RuleType.AUTH_REQUIRED:
            if caller_identity_id:
                return PolicyResult.ALLOW
            return PolicyResult.DENY

        if rule.rule_type == RuleType.OWNER_ONLY:
            if not resource_owner_identity_id:
                return PolicyResult.UNKNOWN
            if caller_identity_id == resource_owner_identity_id:
                return PolicyResult.ALLOW
            return PolicyResult.DENY

        if rule.rule_type == RuleType.PARENT_ACCESS:
            # Requires parent ownership lookup; if untracked, return unknown
            if not resource_owner_identity_id:
                return PolicyResult.UNKNOWN
            if caller_identity_id == resource_owner_identity_id:
                return PolicyResult.ALLOW
            return PolicyResult.DENY

        return PolicyResult.UNKNOWN
