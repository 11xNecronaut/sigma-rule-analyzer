
"""
Detection Rule Quality Validator

Validates metadata and basic configuration of
Elastic-compatible detection rule records.
"""

VALID_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical"
}


def finding(level, code, message):
    return {
        "level": level,
        "code": code,
        "message": message
    }


def validate_rule(rule):
    """Validate an individual detection rule."""

    findings = []

    if not isinstance(rule, dict):
        return [
            finding(
                "error",
                "INVALID_RECORD",
                "Detection rule must be a JSON object."
            )
        ]

    # Rule identification
    identifier = rule.get("rule_id") or rule.get("id")
    name = rule.get("name") or rule.get("title")

    if not identifier:
        findings.append(finding(
            "warning",
            "MISSING_IDENTIFIER",
            "Rule has no rule_id or id."
        ))

    if not name:
        findings.append(finding(
            "error",
            "MISSING_NAME",
            "Rule has no name or title."
        ))

    # Description
    description = rule.get("description")

    if not isinstance(description, str) or not description.strip():
        findings.append(finding(
            "warning",
            "MISSING_DESCRIPTION",
            "Rule description is missing or empty."
        ))

    # Rule type and query
    rule_type = rule.get("type")
    query = rule.get("query")
    language = rule.get("language")

    if not rule_type:
        findings.append(finding(
            "warning",
            "MISSING_TYPE",
            "Rule type is not specified."
        ))

    if rule_type == "query":

        if not isinstance(query, str) or not query.strip():
            findings.append(finding(
                "error",
                "MISSING_QUERY",
                "Query-based rule has no valid query."
            ))

        if not isinstance(language, str) or not language.strip():
            findings.append(finding(
                "error",
                "MISSING_LANGUAGE",
                "Query-based rule has no query language."
            ))

    # Severity
    severity = rule.get("severity")

    if not isinstance(severity, str) or severity.lower() not in VALID_SEVERITIES:
        findings.append(finding(
            "warning",
            "INVALID_SEVERITY",
            "Severity is missing or outside the recognised Elastic severity values."
        ))

    # Risk score
    risk_score = rule.get("risk_score")

    if risk_score is not None:
        if (
            isinstance(risk_score, bool)
            or not isinstance(risk_score, (int, float))
            or not 0 <= risk_score <= 100
        ):
            findings.append(finding(
                "error",
                "INVALID_RISK_SCORE",
                "Risk score must be a numeric value between 0 and 100."
            ))

    # Index patterns
    if "index" in rule:
        indexes = rule["index"]

        if (
            not isinstance(indexes, list)
            or not all(
                isinstance(index, str) and index.strip()
                for index in indexes
            )
        ):
            findings.append(finding(
                "error",
                "INVALID_INDEX",
                "Index must be a list of non-empty strings."
            ))

    # Tags
    if "tags" in rule:
        tags = rule["tags"]

        if (
            not isinstance(tags, list)
            or not all(isinstance(tag, str) for tag in tags)
        ):
            findings.append(finding(
                "warning",
                "INVALID_TAGS",
                "Tags should be a list of strings."
            ))

    # MITRE ATT&CK metadata
    if "threat" in rule:

        threat = rule["threat"]

        if not isinstance(threat, list):
            findings.append(finding(
                "warning",
                "INVALID_THREAT_MAPPING",
                "Threat metadata should be a list."
            ))
        else:
            for item in threat:

                if not isinstance(item, dict):
                    findings.append(finding(
                        "warning",
                        "INVALID_THREAT_ENTRY",
                        "Threat entry must be a JSON object."
                    ))
                    continue

                if item.get("framework") == "MITRE ATT&CK":

                    if not isinstance(item.get("tactic"), dict):
                        findings.append(finding(
                            "warning",
                            "MISSING_ATTACK_TACTIC",
                            "MITRE mapping has no valid tactic object."
                        ))

                    techniques = item.get("technique", [])

                    if not isinstance(techniques, list):
                        findings.append(finding(
                            "warning",
                            "INVALID_ATTACK_TECHNIQUE",
                            "MITRE techniques must be a list."
                        ))

    return findings


def validate_collection(rules):
    """Validate a collection and identify duplicate identifiers."""

    findings = []
    identifiers = {}

    for position, rule in enumerate(rules):

        rule_findings = validate_rule(rule)

        identifier = (
            rule.get("rule_id") or rule.get("id")
            if isinstance(rule, dict)
            else None
        )

        for issue in rule_findings:
            findings.append({
                "rule_index": position,
                "rule_id": identifier,
                **issue
            })

        if identifier:
            identifiers.setdefault(identifier, []).append(position)

    # Duplicate identifiers
    for identifier, positions in identifiers.items():

        if len(positions) > 1:
            for position in positions[1:]:
                findings.append({
                    "rule_index": position,
                    "rule_id": identifier,
                    "level": "error",
                    "code": "DUPLICATE_RULE_ID",
                    "message": "Rule identifier appears more than once."
                })

    errors = sum(
        item["level"] == "error"
        for item in findings
    )

    warnings = sum(
        item["level"] == "warning"
        for item in findings
    )

    invalid_indexes = {
        item["rule_index"]
        for item in findings
        if item["level"] == "error"
    }

    return {
        "total_rules": len(rules),
        "valid_rules": len(rules) - len(invalid_indexes),
        "invalid_rules": len(invalid_indexes),
        "errors": errors,
        "warnings": warnings,
        "findings": findings
    }
