
# Testing and Validation

This directory contains automated tests and validation procedures for Sigma Detection Intelligence.

The testing scope focuses on the reliability of detection rule ingestion, NDJSON parsing, archive handling and rule metadata extraction.

## Testing Objectives

- Verify NDJSON file parsing.
- Validate ZIP archive ingestion.
- Confirm recursive category extraction.
- Identify malformed JSON records.
- Verify rule metadata preservation.
- Check detection rule identifiers.
- Evaluate error handling for invalid data sources.

## Test Components

| Component | Validation objective |
|---|---|
| Rule loader | Verify that detection records are loaded correctly |
| NDJSON parser | Check JSON parsing and malformed records |
| ZIP ingestion | Verify reading nested NDJSON files |
| Category extraction | Verify directory-based categorisation |
| Metadata extraction | Confirm rule identifiers and attributes are preserved |
| Error handling | Check behaviour when archives or data sources are invalid |

## Running Tests

From the repository root:

```bash
python3 -m unittest discover -s tests -v
```

## Testing Philosophy

A successfully loaded rule is not necessarily a valid or effective detection.

These tests primarily validate data ingestion and application behaviour. Detection effectiveness requires separate testing against representative security event data.
