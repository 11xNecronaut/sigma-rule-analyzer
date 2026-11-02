
# Detection Rule Collection

This project uses a locally maintained collection of Elastic-compatible detection rules in NDJSON format.

## Directory Structure

The collection contains categorised detection rules organised into nested directories.

```text
ndjson/
├── application/
├── cloud/
├── apt/
├── compliance/
├── linux/
├── windows/
└── ...
```

## Data Format

The collection contains Elastic-compatible detection rule records stored in NDJSON format.

Each record represents a detection rule containing metadata such as:

- Rule name and description
- Detection query
- Severity and risk score
- Data-source index patterns
- Tags and MITRE ATT&CK mappings

## Local Configuration

The complete rule collection is not bundled with this repository.

To use the application, obtain the compatible NDJSON collection and configure its local directory using:

```bash
export SIGMA_RULES_DIR="/path/to/rules/ndjson"
```

The application recursively searches nested directories for `.ndjson` files.

## Data Attribution

Imported detection content remains subject to the original repository's licensing and attribution requirements.
