
# Detection Rule Analysis

This directory contains technical documentation covering the structure, logic, metadata and classification of security detection rules analysed by Sigma Detection Intelligence.

The objective is to understand how detection rules represent suspicious behaviour, what conditions they evaluate, which telemetry sources they depend on, and how their detection objectives relate to the MITRE ATT&CK framework.

## Documentation

| Document | Description |
|---|---|
| [Rule Format](rule_format.md) | Structure and components of Elastic-compatible NDJSON detection rules |
| [Detection Logic](detection_logic.md) | Query conditions, field matching, detection types and false positives |
| [MITRE ATT&CK Mapping](mitre_mapping.md) | Understanding tactics, techniques and detection coverage |

## Analysis Scope

The analysis focuses on:

- Detection rule metadata and identifiers.
- Rule descriptions and detection objectives.
- Query languages and detection conditions.
- Severity and risk-score classifications.
- Index patterns and telemetry dependencies.
- Rule tags and MITRE ATT&CK associations.
- Detection limitations and potential false positives.

## Data Format

The primary detection collection uses Elastic-compatible detection rule records stored in NDJSON format.

Each NDJSON line represents a structured JSON record.

These records are platform-specific detection objects and should not automatically be treated as original Sigma YAML rules.

## Analysis Workflow

1. Identify a detection rule.
2. Examine its metadata and description.
3. Identify its detection type and query language.
4. Understand the conditions used by its query.
5. Inspect required data sources and index patterns.
6. Examine severity and risk score.
7. Review associated MITRE ATT&CK mappings.
8. Document detection limitations and potential false positives.

## Important Distinction

A detection rule describes conditions that can identify particular activity within event data.

The presence of a detection rule does not establish that an attack has occurred. Detection effectiveness depends on telemetry availability, query compatibility, field mappings and validation against relevant events.
