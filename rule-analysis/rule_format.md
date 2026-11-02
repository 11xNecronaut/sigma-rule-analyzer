
# Detection Rule Format Analysis

## 1. Introduction

The detection collection used by Sigma Detection Intelligence consists of Elastic-compatible detection rules stored in Newline Delimited JSON (NDJSON) format.

NDJSON is a structured data format where each line contains an independent JSON object.

Unlike conventional JSON files containing one large array, NDJSON allows individual records to be processed line by line.

This makes it useful for analysing large collections of detection rules.

## 2. NDJSON Structure

A simplified example of an Elastic-compatible detection rule:

```json
{
  "name": "Example Suspicious Process Detection",
  "description": "Identifies a potentially suspicious process execution pattern.",
  "enabled": false,
  "risk_score": 65,
  "severity": "high",
  "type": "query",
  "language": "lucene",
  "index": [
    "winlogbeat-*",
    "logs-*"
  ],
  "query": "process.name: \"example.exe\"",
  "tags": [
    "attack.execution",
    "attack.t1059"
  ],
  "rule_id": "example-rule-id",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0002",
        "name": "Execution"
      },
      "technique": [
        {
          "id": "T1059",
          "name": "Command and Scripting Interpreter"
        }
      ]
    }
  ]
}
```

This is an illustrative example, not a record copied from the collection.

## 3. Important Rule Fields

### Identification and Description

| Field | Purpose |
|---|---|
| `name` | Identifies the detection rule |
| `description` | Describes the behaviour being detected |
| `rule_id` | Provides a unique rule identifier |
| `author` | Identifies the rule author, when supplied |
| `references` | Provides supporting documentation |

### Detection Configuration

| Field | Purpose |
|---|---|
| `type` | Specifies the detection rule type |
| `language` | Identifies the query language |
| `query` | Contains the detection query |
| `index` | Specifies the indices searched by the rule |
| `filters` | Contains additional filtering conditions |

### Risk and Severity

| Field | Purpose |
|---|---|
| `severity` | Classifies the detection severity |
| `risk_score` | Represents the configured risk score |
| `enabled` | Indicates whether the rule is enabled |
| `max_signals` | Defines a configured alert limit |
| `interval` | Defines the scheduled execution interval |

### Threat Classification

| Field | Purpose |
|---|---|
| `tags` | Stores detection labels and classifications |
| `threat` | Contains threat framework mappings |
| `framework` | Identifies the associated framework |
| `tactic` | Describes the associated ATT&CK tactic |
| `technique` | Identifies the relevant ATT&CK technique |

Not every detection record contains every field. Optional fields, schema variations and rule types must be considered during parsing.

## 4. Detection Query Languages

Detection rules may use different query languages depending on their implementation.

Common examples include:

- KQL (Kibana Query Language)
- Lucene
- EQL (Event Query Language)
- ES|QL

The `language` and `type` fields help determine how a query should be interpreted.

A query written for one language cannot automatically be assumed to work in another.

## 5. Detection Rule Metadata

Metadata helps analysts understand the context of a detection without immediately examining the underlying query.

For example:

- Name and description explain detection intent.
- Severity and risk score support prioritisation.
- Index patterns describe expected data locations.
- Tags provide additional classification.
- MITRE ATT&CK associations describe related adversary behaviour.

Metadata provides context, but does not independently establish detection effectiveness.

## 6. Analysis Considerations

When examining a rule, consider:

1. Is the rule's detection objective clearly defined?
2. Does the query use appropriate event fields?
3. Are the required indices available?
4. Is the query compatible with the stated language?
5. Are the severity and risk score reasonable?
6. Are the MITRE mappings relevant?
7. Are potential false positives documented?

## 7. Conclusion

Understanding the underlying structure of detection rules is essential for analysing security detection content.

Structured rule metadata allows detection content to be searched, classified and examined systematically.

The analysis performed by this project focuses on understanding detection configuration and metadata rather than treating the presence of a rule as proof of a successful detection.
