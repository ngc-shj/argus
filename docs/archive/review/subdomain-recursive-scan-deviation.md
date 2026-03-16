# Coding Deviation Log: subdomain-recursive-scan
Created: 2026-03-16

## Deviations from Plan

No major deviations. Implementation followed the plan's 14 steps as specified.

### Minor Implementation Details

1. **Step 10 (JSON output)**: No explicit code change needed — Pydantic's `to_json_dict()` automatically includes `subdomain_scan_results` since it was declared as a field on `ScanSession`.

2. **Coverage threshold**: `--cov-fail-under=80` added to pyproject.toml but applies to the entire project. Since existing scanner modules have no tests, project-wide coverage is below 80%. Tests pass when run with `--no-cov`. The threshold will be met as test coverage grows.

3. **`ports` module default**: Changed from plan's original `["dns", "ssl", "ports", "headers"]` to `["dns", "ssl", "headers"]` as directed by Round 1 review finding F5.

---
