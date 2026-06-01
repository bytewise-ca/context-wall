"""Control mapping definitions for HIPAA, SOC2 Type II, and FedRAMP Moderate.

Task 8.7: walk active policy rules, map to framework controls, set satisfied flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ControlRef:
    framework: str
    control_id: str
    description: str


# Built-in control mappings per rule name prefix / action type
RULE_CONTROL_MAP: dict[str, list[ControlRef]] = {
    # HIPAA minimum-necessary rule
    "hipaa-minimum-necessary": [
        ControlRef("hipaa", "45 CFR 164.502(b)", "Minimum Necessary Standard"),
        ControlRef("hipaa", "45 CFR 164.514(d)", "Minimum Necessary - workforce access"),
    ],
    # HIPAA audit control
    "hipaa-audit-control": [
        ControlRef("hipaa", "45 CFR 164.312(b)", "Audit Controls"),
    ],
    # Untrusted source sanitization
    "untrusted-source-sanitization": [
        ControlRef("soc2", "CC6.1", "Logical and Physical Access Controls"),
        ControlRef("soc2", "CC6.6", "External Threats - logical access controls"),
        ControlRef("fedramp", "SI-3", "Malicious Code Protection"),
    ],
    # Secret detection
    "block_secrets": [
        ControlRef("soc2", "CC6.1", "Logical and Physical Access Controls"),
        ControlRef("fedramp", "AC-3", "Access Enforcement"),
    ],
    # PII redaction
    "redact_pii": [
        ControlRef("hipaa", "45 CFR 164.502(b)", "Minimum Necessary Standard"),
        ControlRef("gdpr", "Art. 5(1)(c)", "Data Minimisation"),
    ],
    # SOC2 logging
    "soc2-policy-action-logging": [
        ControlRef("soc2", "CC7.2", "System Monitoring"),
        ControlRef("soc2", "CC8.1", "Change Management"),
        ControlRef("fedramp", "AU-2", "Audit Events"),
        ControlRef("fedramp", "AU-9", "Protection of Audit Information"),
    ],
}


@dataclass
class ControlMapping:
    framework: str
    control_id: str
    description: str
    satisfied: bool
    rule_name: str


def resolve_control_mappings(
    fired_rule_names: set[str],
    requested_framework: str | None = None,
) -> list[ControlMapping]:
    """Map fired rules to compliance controls.

    satisfied=True when the rule fired in the session (evidence exists).
    satisfied=False when the control is required but the rule did not fire.
    """
    mappings: list[ControlMapping] = []
    seen: set[tuple[str, str]] = set()

    for rule_name, refs in RULE_CONTROL_MAP.items():
        for ref in refs:
            if requested_framework and ref.framework != requested_framework:
                continue
            key = (ref.framework, ref.control_id)
            if key in seen:
                continue
            seen.add(key)
            mappings.append(ControlMapping(
                framework=ref.framework,
                control_id=ref.control_id,
                description=ref.description,
                satisfied=rule_name in fired_rule_names,
                rule_name=rule_name,
            ))

    return mappings
