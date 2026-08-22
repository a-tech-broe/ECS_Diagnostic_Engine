"""Diagnosis rules. Importing this package registers every built-in rule."""

from .base import Rule, RuleContext, all_rules, register, rule_ids
from . import dependencies, deployment, resources, tasks, traffic  # noqa: F401  (registration)

__all__ = ["Rule", "RuleContext", "all_rules", "register", "rule_ids"]
