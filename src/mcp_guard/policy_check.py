"""Offline, payload-free policy diagnostics; warnings never change enforcement."""

import json
from pathlib import Path

import yaml

from .policy import Policy


def check_policy(path):
    report = {"errors": [], "warnings": []}
    try:
        config = yaml.safe_load(Path(path).read_text())
        Policy(config)
    except (ValueError, OSError, yaml.YAMLError):
        report["errors"].append({"code": "invalid_policy", "location": "$"})
        return report
    for section, rules in config.items():
        seen = set()
        denied = {r["match"] for r in rules if not r["allow"]}
        for index, rule in enumerate(rules):
            location = f"{section}[{index}]"
            canonical = json.dumps(rule, sort_keys=True)
            codes = []
            if canonical in seen:
                codes.append("duplicate_rule")
            seen.add(canonical)
            if rule["allow"] and any(c in rule["match"] for c in "*?["):
                codes.append("broad_grant")
            if rule["allow"] and rule["match"] in denied:
                codes.append("deny_shadows_grant")
            report["warnings"].extend(
                {"code": code, "location": location} for code in codes
            )
    return report
