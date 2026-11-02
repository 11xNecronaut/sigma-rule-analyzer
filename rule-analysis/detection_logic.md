
# Detection Logic Analysis

## 1. Introduction

Detection logic defines the conditions used to identify potentially suspicious activity within collected event data.

A detection rule evaluates available telemetry against specified fields, values, patterns and logical conditions.

Understanding detection logic requires examining more than the rule name or severity classification.

The query, event-field dependencies, data source and execution configuration determine what the detection can identify.

## 2. Query-Based Detection

Query-based rules search event data for records matching defined conditions.

For example, consider an illustrative Lucene query:

```text
process.name: "powershell.exe"
AND process.command_line: "*-EncodedCommand*"
```

The intention is to identify PowerShell process events where the command line contains an encoded-command argument.

This query represents a detection condition, not proof of malicious activity.

A legitimate administrator may use the same functionality.

## 3. Detection Components

### Field Matching

Field matching evaluates values stored in event records.

Examples include:

- `process.name`
- `process.executable`
- `process.command_line`
- `user.name`
- `host.name`
- `process.parent.name`

The actual field names depend on the telemetry source, event schema and platform integration.

### Logical Operators

Queries commonly use logical operators to combine conditions.

| Operator | Meaning |
|---|---|
| AND | All specified conditions must match |
| OR | At least one specified condition must match |
| NOT | Excludes matching conditions |

An incorrect combination of logical operators may cause a detection to match too many or too few events.

### Pattern Matching

Detection logic may use exact values, wildcard patterns, ranges or other supported matching methods.

For example:

```text
process.name: "cmd.exe"
```

An exact match.

```text
process.command_line: "*EncodedCommand*"
```

A wildcard-based command-line match, assuming the selected query language and field mapping support the syntax.

## 4. Detection Types

Security platforms support different detection approaches.

### Query-Based Detection

Searches event records for matching conditions.

### Event Correlation

Connects multiple related events to identify a sequence or pattern of activity.

### Threshold-Based Detection

Identifies repeated activity exceeding a configured threshold.

For example, multiple failed authentication attempts within a specified period.

### Sequence-Based Detection

Identifies a defined order of events.

For example, a process creation event followed by another related event.

These approaches have different data requirements and detection capabilities.

## 5. Data Source Dependencies

Detection logic is only as useful as the telemetry available to evaluate it.

A detection targeting Windows process creation requires appropriate process telemetry.

Potential sources include:

- Windows Security Event Logs.
- Sysmon.
- Endpoint Detection and Response telemetry.
- Elastic Agent integrations.

Missing logs, inconsistent field names, incomplete event collection and incorrect index patterns may prevent an otherwise valid rule from working.

## 6. False Positive Analysis

A false positive occurs when a detection identifies activity that satisfies its matching conditions but is not actually malicious.

Consider an encoded PowerShell command.

Potential legitimate sources include:

- Administrative automation.
- Software deployment.
- System maintenance.
- Enterprise management scripts.

An analyst should investigate the surrounding context rather than immediately classify the activity as malicious.

Useful contextual information includes:

- Executing user.
- Hostname.
- Parent process.
- Command-line arguments.
- Execution time.
- Related process activity.
- Network connections.

## 7. Detection Quality Considerations

Detection analysis should consider:

| Area | Question |
|---|---|
| Field accuracy | Are the correct event fields being evaluated? |
| Data availability | Is the required telemetry collected? |
| Query compatibility | Is the query valid for its configured language? |
| Detection precision | Does the rule generate excessive false positives? |
| Coverage | Does the rule identify the intended behaviour? |
| Performance | Can the query run efficiently against the intended data? |

## 8. Analytical Limitations

A detection query may identify suspicious characteristics without understanding the full context of the event.

For example, encoded command execution can be suspicious but is not inherently malicious.

Similarly, a rule that identifies one known execution pattern may fail to identify another variation of the same behaviour.

Detection engineering therefore requires continuous evaluation, contextual analysis and refinement.

## 9. Conclusion

Detection logic translates security monitoring requirements into conditions that can be evaluated against event data.

Understanding query construction, logical operators, event fields and telemetry dependencies is fundamental to analysing the quality and limitations of security detections.
