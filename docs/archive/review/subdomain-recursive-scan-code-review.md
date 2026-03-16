# Code Review: subdomain-recursive-scan
Date: 2026-03-16
Review round: 2

## Changes from Previous Round
Round 1: 12 findings (Critical 5, Major 5, Minor 2). All resolved in review(1) commit.
Round 2: All fixes verified. 3 new Minor/Low findings (accepted).

## Functionality Findings
All resolved. Minor residual: timeout test scheduling dependency (accepted).

## Security Findings
All resolved. Low residual: result.domain in AI prompt not sanitized (mitigated by domain regex validation).

## Testing Findings
All resolved. Low residual: no regression test for get_running_loop fix (low risk).

## Adjacent Findings
None.

## Resolution Status

### [F1] Critical: Timeout partial results empty
- Action: Collect results from completed tasks in except TimeoutError block
- Modified file: subdomain_coordinator.py:165-183

### [S1] Critical: HTML XSS resolved_ips
- Action: Added html.escape() to IP values in DNS subdomain list
- Modified file: html.py:460

### [S2] Critical: AI prompt injection via result.error
- Action: Strip scan_data delimiters, truncate to 500 chars
- Modified file: analyzer.py:185-188

### [S4] Major: Subdomain scope bypass via endswith
- Action: Changed to proper subdomain boundary check with "." prefix
- Modified file: coordinator.py:830-831

### [F2] Major: FR-9 discovery source warning
- Action: Added warning when neither crtsh nor subdomain_enum enabled
- Modified file: coordinator.py:809

### [F3] Major: CLI ValidationError handling
- Action: Wrapped ScanOptions construction in try/except
- Modified file: app.py:197-231

### [F5/S6] Minor: asyncio.get_event_loop deprecated
- Action: Replaced with asyncio.get_running_loop
- Modified file: subdomain_coordinator.py:190

### [T1] Critical: Timeout test false-positive
- Action: Rewrote with real async timing and selective_wait_for
- Modified file: test_subdomain_coordinator.py:309-374

### [T2] Critical: DNS-first gating test incomplete
- Action: Added dns_scanner.called assertion + ssl-only variant
- Modified file: test_subdomain_coordinator.py:196-226

### [T6] Major: IPv4-mapped hex form test missing
- Action: Added ::ffff:c0a8:101 test case
- Modified file: test_subdomain_scan_model.py:202-205

### [T3] Major: Misleading comment + boundary case
- Action: Fixed comment, added (0,50,0) parametrize case
- Modified file: test_subdomain_coordinator.py:84-128

### [T4] Major: Error isolation assertion
- Action: Added negative assertion for broken.example.com
- Modified file: test_subdomain_coordinator.py:298-305
