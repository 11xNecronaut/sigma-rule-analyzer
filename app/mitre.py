
"""
MITRE ATT&CK Coverage Analysis

Analyses ATT&CK tactic and technique associations
across Elastic-compatible detection rule records.

Counts unique rules, not individual mapping entries.
"""

import re
from collections import defaultdict


TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
TACTIC_PATTERN = re.compile(r"^TA\d{4}$", re.I)

# ATT&CK tactic slugs commonly found in rule tags.
TACTIC_NAMES = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}


def rule_key(rule, index):
    """Return a stable per-record key for counting unique rules."""
    return str(
        rule.get("_local_id")
        or rule.get("rule_id")
        or rule.get("id")
        or f"record:{index}"
    )


def rule_label(rule):
    """Return a readable rule name."""
    return (
        rule.get("name")
        or rule.get("title")
        or "Unnamed Rule"
    )


def add_tactic(collection, tactic_id, name):
    """Normalise and store a tactic."""
    tactic_id = str(tactic_id or "").strip().upper()
    name = str(name or "").strip()

    if not TACTIC_PATTERN.fullmatch(tactic_id):
        tactic_id = ""

    if not name and tactic_id:
        name = tactic_id

    if not name:
        return None

    key = tactic_id or name.lower()

    entry = collection.setdefault(
        key,
        {
            "id": tactic_id or None,
            "name": name,
        }
    )

    # Prefer a descriptive name over an ID-only fallback.
    if name and name != tactic_id:
        entry["name"] = name

    return key


def add_technique(collection, technique_id, name):
    """Normalise and store an ATT&CK technique or sub-technique."""
    technique_id = str(technique_id or "").strip().upper()
    name = str(name or "").strip()

    if not TECHNIQUE_PATTERN.fullmatch(technique_id):
        return None

    key = technique_id

    entry = collection.setdefault(
        key,
        {
            "id": technique_id,
            "name": name or technique_id,
        }
    )

    if name:
        entry["name"] = name

    return key


def analyse_rule(rule):
    """
    Extract ATT&CK mappings from one detection record.

    Sources:
      1. Elastic threat metadata.
      2. ATT&CK tags such as attack.execution and attack.t1059.
    """
    tactic_entries = {}
    technique_entries = {}
    sources = set()

    if not isinstance(rule, dict):
        return tactic_entries, technique_entries, sources

    # ----------------------------------------
    # Source 1: Elastic threat metadata
    # ----------------------------------------

    threat = rule.get("threat", [])

    if isinstance(threat, list):

        for item in threat:

            if not isinstance(item, dict):
                continue

            framework = str(item.get("framework", "")).lower()
            tactic = item.get("tactic", {})
            techniques = item.get("technique", [])

            if not isinstance(tactic, dict):
                tactic = {}

            tactic_id = tactic.get("id")
            tactic_name = tactic.get("name")

            has_attack_id = (
                bool(tactic_id)
                and bool(TACTIC_PATTERN.fullmatch(str(tactic_id)))
            )

            has_attack_name = any(
                str(value or "").lower() in
                {name.lower() for _, name in TACTIC_NAMES.values()}
                for value in [tactic_name]
            )

            is_mitre = (
                "mitre" in framework
                or has_attack_id
                or has_attack_name
            )

            if not is_mitre:
                continue

            sources.add("threat_metadata")

            if tactic_id or tactic_name:
                tactic_key = add_tactic(
                    tactic_entries, tactic_id, tactic_name
                )
            else:
                tactic_key = None

            if not isinstance(techniques, list):
                continue

            for technique in techniques:

                if not isinstance(technique, dict):
                    continue

                technique_key = add_technique(
                    technique_entries,
                    technique.get("id"),
                    technique.get("name")
                )

                if technique_key:
                    if tactic_key:
                        technique_entries[technique_key][
                            "tactics"
                        ] = technique_entries[technique_key].get(
                            "tactics", set()
                        )

                        technique_entries[technique_key][
                            "tactics"
                        ].add(tactic_key)

    # ----------------------------------------
    # Source 2: ATT&CK tags
    # ----------------------------------------

    tags = rule.get("tags", [])

    tag_tactic_keys = set()
    tag_technique_keys = set()

    if isinstance(tags, list):

        for tag in tags:

            if not isinstance(tag, str):
                continue

            value = tag.strip().lower()

            if not value.startswith("attack."):
                continue

            identifier = value[len("attack."):]
            identifier = identifier.replace("_", "-")

            # Technique or sub-technique tag
            if TECHNIQUE_PATTERN.fullmatch(identifier.upper()):

                technique_key = add_technique(
                    technique_entries,
                    identifier,
                    None
                )

                if technique_key:
                    tag_technique_keys.add(technique_key)
                    sources.add("attack_tags")

            # Tactic tag
            elif identifier in TACTIC_NAMES:

                tactic_id, tactic_name = TACTIC_NAMES[identifier]

                tactic_key = add_tactic(
                    tactic_entries,
                    tactic_id,
                    tactic_name
                )

                if tactic_key:
                    tag_tactic_keys.add(tactic_key)
                    sources.add("attack_tags")

    # Associate techniques with tactics found in the same rule's tags
    for technique_key in tag_technique_keys:

        technique_entries[technique_key].setdefault(
            "tactics", set()
        ).update(tag_tactic_keys)

    return tactic_entries, technique_entries, sources

    """
    Analyse ATT&CK coverage across a collection of rules.

    A rule is considered mapped if it has at least one
    recognised ATT&CK tactic or technique association.
    """

    tactics = {}
    techniques = {}

    mapped_rule_keys = set()
    unmapped = []

    source_rule_counts = defaultdict(set)

    for index, rule in enumerate(rules):

        if not isinstance(rule, dict):
            continue

        key = rule_key(rule, index)

        rule_tactics, rule_techniques, sources = analyse_rule(rule)

        is_mapped = bool(rule_tactics or rule_techniques)

        if is_mapped:
            mapped_rule_keys.add(key)
        else:
            unmapped.append({
                "id": rule.get("rule_id") or rule.get("id"),
                "name": rule_label(rule),
                "category": rule.get("_category", "unknown"),
            })

        for source in sources:
            source_rule_counts[source].add(key)

        # Add each rule once to each tactic.
        for tactic_key, tactic in rule_tactics.items():

            entry = tactics.setdefault(
                tactic_key,
                {
                    "id": tactic["id"],
                    "name": tactic["name"],
                    "rules": set(),
                    "techniques": set(),
                }
            )

            entry["rules"].add(key)

        # Add each rule once to each technique.
        for technique_key, technique in rule_techniques.items():

            entry = techniques.setdefault(
                technique_key,
                {
                    "id": technique["id"],
                    "name": technique["name"],
                    "rules": set(),
                    "tactics": set(),
                }
            )

            entry["rules"].add(key)

            entry["tactics"].update(
                technique.get("tactics", set())
            )

        # Link mapped techniques to their associated tactics.
        for tactic_key in rule_tactics:

            for technique_key in rule_techniques:

                if tactic_key in technique_rules_for(
                    rule_techniques[technique_key]
                ):
                    tactics[tactic_key]["techniques"].add(
                        technique_key
                    )

    total = len(rules)
    mapped = len(mapped_rule_keys)
    unmapped_count = total - mapped

    tactic_results = []

    for entry in tactics.values():

        tactic_results.append({
            "id": entry["id"],
            "name": entry["name"],
            "rule_count": len(entry["rules"]),
            "technique_count": len(entry["techniques"]),
        })

    technique_results = []

    for entry in techniques.values():

        technique_results.append({
            "id": entry["id"],
            "name": entry["name"],
            "rule_count": len(entry["rules"]),
            "tactics": sorted(entry["tactics"]),
        })

    tactic_results.sort(
        key=lambda item: (-item["rule_count"], item["name"])
    )

    technique_results.sort(
        key=lambda item: (-item["rule_count"], item["id"])
    )

    if total:
        percentage = round((mapped / total) * 100, 2)
    else:
        percentage = 0.0

    return {
        "total_rules": total,
        "mapped_rules": mapped,
        "unmapped_rules": unmapped_count,
        "coverage_percentage": percentage,
        "unique_tactics": len(tactic_results),
        "unique_techniques": len(technique_results),
        "mapping_sources": {
            source: len(keys)
            for source, keys in source_rule_counts.items()
        },
        "tactics": tactic_results,
        "techniques": technique_results,
        "unmapped_rule_samples": unmapped[:100],
        "unmapped_samples_limit": 100,
    }


def technique_rules_for(technique):
    """Return tactic associations already extracted for a technique."""
    return technique.get("tactics", set())


def analyze_mitre(rules):
    """
    Analyse MITRE ATT&CK associations across detection rules.
    Counts unique rule records per tactic and technique.
    """

    tactics = {}
    techniques = {}

    mapped_rule_keys = set()
    source_rule_keys = {}
    unmapped = []

    total = len(rules)

    for index, rule in enumerate(rules):

        if not isinstance(rule, dict):
            unmapped.append({
                "id": None,
                "name": "Invalid record",
                "category": "unknown"
            })
            continue

        key = str(
            rule.get("_local_id")
            or rule.get("rule_id")
            or rule.get("id")
            or f"record:{index}"
        )

        rule_tactics, rule_techniques, sources = analyse_rule(rule)

        # Determine whether this rule has recognised ATT&CK mappings.
        if rule_tactics or rule_techniques:
            mapped_rule_keys.add(key)
        else:
            unmapped.append({
                "id": rule.get("rule_id") or rule.get("id"),
                "name": rule.get("name") or rule.get("title") or "Unnamed Rule",
                "category": rule.get("_category", "unknown")
            })

        # Track mapping sources.
        for source in sources:
            source_rule_keys.setdefault(source, set()).add(key)

        # Aggregate tactic associations.
        for tactic_key, tactic in rule_tactics.items():

            entry = tactics.setdefault(
                tactic_key,
                {
                    "id": tactic.get("id"),
                    "name": tactic.get("name"),
                    "rules": set(),
                    "techniques": set()
                }
            )

            entry["rules"].add(key)

        # Aggregate technique associations.
        for technique_key, technique in rule_techniques.items():

            entry = techniques.setdefault(
                technique_key,
                {
                    "id": technique.get("id"),
                    "name": technique.get("name"),
                    "rules": set(),
                    "tactics": set()
                }
            )

            entry["rules"].add(key)

            entry["tactics"].update(
                technique.get("tactics", set())
            )

    # Connect techniques to their associated tactics.
    for technique_key, technique in techniques.items():

        for tactic_key in technique["tactics"]:

            if tactic_key in tactics:
                tactics[tactic_key]["techniques"].add(
                    technique_key
                )

    # Prepare tactic results.
    tactic_results = []

    for tactic in tactics.values():

        tactic_results.append({
            "id": tactic["id"],
            "name": tactic["name"],
            "rule_count": len(tactic["rules"]),
            "technique_count": len(tactic["techniques"])
        })

    tactic_results.sort(
        key=lambda item: (-item["rule_count"], item["name"] or "")
    )

    # Prepare technique results.
    technique_results = []

    for technique in techniques.values():

        associated_tactics = []

        for tactic_key in technique["tactics"]:

            tactic = tactics.get(tactic_key)

            if tactic:
                associated_tactics.append(
                    tactic["id"] or tactic["name"]
                )

        technique_results.append({
            "id": technique["id"],
            "name": technique["name"],
            "rule_count": len(technique["rules"]),
            "tactics": sorted(associated_tactics)
        })

    technique_results.sort(
        key=lambda item: (-item["rule_count"], item["id"])
    )

    mapped = len(mapped_rule_keys)
    unmapped_count = max(0, total - mapped)

    percentage = round(
        (mapped / total) * 100, 2
    ) if total else 0.0

    return {
        "total_rules": total,
        "mapped_rules": mapped,
        "unmapped_rules": unmapped_count,
        "coverage_percentage": percentage,
        "unique_tactics": len(tactic_results),
        "unique_techniques": len(technique_results),
        "mapping_sources": {
            source: len(keys)
            for source, keys in source_rule_keys.items()
        },
        "tactics": tactic_results,
        "techniques": technique_results,
        "unmapped_rule_samples": unmapped[:100],
        "unmapped_samples_limit": 100
    }

