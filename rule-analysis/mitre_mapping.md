
# MITRE ATT&CK Mapping Analysis

## 1. Introduction

MITRE ATT&CK is a knowledge base of adversary tactics, techniques and procedures based on observed cybersecurity activity.

It provides a common classification system for understanding attacker behaviour.

Detection rules can reference MITRE ATT&CK to indicate which adversary behaviours they are intended to identify.

This project examines those associations within the imported Elastic-compatible detection rule collection.

Official reference:

https://attack.mitre.org/

## 2. Tactics and Techniques

MITRE ATT&CK organises adversary behaviour using tactics and techniques.

### Tactics

Tactics describe an adversary's operational objective.

Examples include:

| Tactic | ID | General objective |
|---|---|---|
| Initial Access | TA0001 | Gain an initial foothold |
| Execution | TA0002 | Run malicious code |
| Persistence | TA0003 | Maintain access |
| Privilege Escalation | TA0004 | Obtain higher permissions |
| Defense Evasion | TA0005 | Avoid security detection |
| Credential Access | TA0006 | Obtain credentials |
| Discovery | TA0007 | Understand the environment |
| Lateral Movement | TA0008 | Move between systems |
| Collection | TA0009 | Gather relevant information |
| Exfiltration | TA0010 | Remove collected information |
| Impact | TA0040 | Affect system availability or integrity |

### Techniques

Techniques describe how an adversary attempts to achieve a tactical objective.

For example:

**T1059 - Command and Scripting Interpreter**

An adversary may use command interpreters and scripting environments to execute instructions.

**T1059.001 - PowerShell**

A specific sub-technique involving PowerShell execution.

Official reference:

https://attack.mitre.org/techniques/T1059/001/

## 3. Mapping Structure in Detection Rules

Elastic-compatible detection rules may include MITRE ATT&CK metadata through the `threat` field.

A simplified example:

```json
{
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

A rule may contain several tactics or techniques.

The mapping must therefore be treated as a collection of associations rather than a single classification.

## 4. Analysing ATT&CK Coverage

MITRE ATT&CK mappings can be used to examine which adversary behaviours are represented in a detection rule collection.

Useful analysis dimensions include:

- Total rules associated with each tactic.
- Number of distinct rules associated with each technique.
- Techniques with the highest rule coverage.
- Techniques with little or no mapped coverage.
- Rules containing multiple technique associations.
- Rules without ATT&CK metadata.

## 5. Coverage Calculation

A basic technique coverage count can be calculated by identifying unique rule identifiers associated with each technique.

For example:

| Technique | Associated rules |
|---|---:|
| T1059 | 24 |
| T1059.001 | 12 |
| T1053.005 | 8 |
| T1110 | 15 |

These are illustrative numbers, not measured results from the project's dataset.

A technique count should count each unique rule once per technique.

A single rule may map to several techniques, so technique counts can overlap.

## 6. Interpreting Coverage

A high number of detection rules associated with a technique does not automatically indicate strong detection coverage.

Several rules may:

- Detect nearly identical activity.
- Depend on the same event source.
- Have overlapping query conditions.
- Cover only a narrow variation of a technique.
- Generate substantial false-positive activity.

Similarly, a technique with few mapped rules is not necessarily completely unmonitored.

Detection coverage analysis should consider rule quality, telemetry availability, deployment status and validation results.

## 7. Mapping Limitations

MITRE ATT&CK associations are contextual metadata.

A technique mapping does not prove that a rule detects every instance of that behaviour.

Incorrect or outdated mappings can also affect analysis.

Important considerations include:

1. Relevance of the mapped technique.
2. Correct tactic classification.
3. Technique and sub-technique specificity.
4. ATT&CK framework version.
5. Availability of the necessary telemetry.
6. Evidence of detection effectiveness.

## 8. Future Analysis

Potential improvements to ATT&CK analysis include:

- Tactic-wise rule distribution.
- Technique-wise detection inventory.
- Detection coverage visualisation.
- Identification of rules without ATT&CK mappings.
- Duplicate and overlapping technique analysis.
- ATT&CK framework version tracking.

## 9. Conclusion

MITRE ATT&CK mapping provides a structured way to understand the adversary behaviours represented by a detection rule collection.

However, mapping counts should not be confused with actual defensive capability.

A meaningful detection coverage assessment must consider the detection logic, event sources, rule quality and validation evidence alongside the ATT&CK classification.
