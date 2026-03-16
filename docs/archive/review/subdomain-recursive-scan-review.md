# Plan Review: subdomain-recursive-scan
Date: 2026-03-16
Review round: 2

## Changes from Previous Round
Round 1: Initial review (22 findings). Round 2: All Round 1 findings resolved. 4 new Major + 10 new Minor found and addressed in plan update.

## Functionality Findings

### F1 [Major] Subdomain source normalization inconsistency
- **Problem**: `crtsh_result.discovered_subdomains` has `certificate_ids` list but `subdomain_enum["subdomains"]` is plain `list[str]` with no cert count. Cap prioritization by cert count is non-deterministic for subdomain_enum entries.
- **Impact**: Subdomain_enum sources silently deprioritized regardless of activity.
- **Recommended action**: Define a normalized intermediate structure (`domain: str`, `cert_count: int = 0`) as common representation before cap/prioritization.

### F2 [Major] ScanSession extra="forbid" requires explicit field addition
- **Problem**: `ScanSession` uses `ConfigDict(extra="forbid")`. Plan Step 5 says "Relax model_config if needed" — this is ambiguous. The field must be explicitly added to the class body.
- **Impact**: Runtime `ValidationError` if field added anywhere other than model definition.
- **Recommended action**: Step 5 must state: "Add field to ScanSession class body. Do NOT relax extra='forbid'."

### F3 [Major] Wildcard deduplication before SSRF validation (ordering issue)
- **Problem**: Wildcard dedup pre-resolves subdomains (step 2), but SSRF validation only happens at ScanTarget construction (step 3). A private-IP subdomain may be selected as group representative, then rejected, silently dropping the entire group.
- **Impact**: Legitimate subdomains excluded from scanning.
- **Recommended action**: Apply SSRF IP validation during wildcard dedup step, before grouping. *(Merged with Security Finding S1)*

### F4 [Major] Double DNS resolution (wildcard dedup + DNS-first gating)
- **Problem**: KDD-7 pre-resolves all subdomains for wildcard detection. KDD-8 runs DNS module per subdomain. Two separate DNS resolutions per hostname → 2x DNS queries, TOCTOU inconsistency.
- **Impact**: Doubled DNS load violating NFR-1 spirit. Stale resolution between phases.
- **Recommended action**: Cache DNS results from wildcard dedup phase; pass to DNS module as optimization. Share single resolution cache.

### F5 [Minor] `ports` in default subdomain_modules creates unexpected network load
- **Problem**: Default `["dns", "ssl", "ports", "headers"]` fires 50 port scans × 100 ports = 5000 probes from a single flag.
- **Recommended action**: Change default to `["dns", "ssl", "headers"]`; document ports as opt-in.

### F6 [Minor] No warning when --scan-subdomains has no active subdomain source
- **Problem**: If user enables `--scan-subdomains` without crtsh or subdomain_enum, zero subdomains discovered, silent no-op.
- **Recommended action**: Emit warning if subdomain list empty and subdomain_scan_enabled=True.

### F7 [Minor] Progress callback total stale after wildcard deduplication
- **Problem**: If callback initialized with pre-dedup count, progress never reaches 100%.
- **Recommended action**: Calculate final post-dedup list before scan loop; initialize callback with definitive count.

## Security Findings

### S1 [Major] DNS rebinding / SSRF bypass — resolved IPs not validated
- **Problem**: `validate_domain()` only checks domain string format. `validate_ip()` only runs for IP-based targets. After DNS resolution, a subdomain could resolve to 169.254.169.254 (cloud metadata) without triggering any IP validation.
- **Impact**: Scanner becomes SSRF probe against operator's own infrastructure.
- **Recommended action**: After wildcard DNS resolution, validate each resolved IP against `BLOCKED_IP_RANGES` and `CLOUD_METADATA_IPS`. Skip subdomain with warning if private IP detected.
- *(Overlaps with F3 — both address SSRF validation ordering)*

### S2 [Major] IPv6 SSRF coverage gap (pre-existing, amplified by this feature)
- **Problem**: `validate_ip()` in target.py applies link-local and cloud-metadata checks only for IPv4 (`isinstance(ip, IPv4Address)`). IPv6 link-local (`fe80::/10`) and IPv4-mapped IPv6 (`::ffff:169.254.169.254`) bypass all checks.
- **Impact**: Subdomain resolving to IPv6 private ranges passes SSRF validation.
- **Recommended action**: Extend `validate_ip()`: check `is_link_local` for IPv6; extract embedded IPv4 from IPv4-mapped addresses and validate.

### S3 [Minor] Module allowlist enforced only at CLI layer
- **Problem**: `subdomain_modules` validation at CLI parse time only; direct `ScanOptions` construction bypasses it.
- **Recommended action**: Add `field_validator` on `subdomain_modules` in `ScanOptions` Pydantic model.

### S4 [Minor] No hard blob size limit for SQLite storage
- **Problem**: Warning at 10MB but no rejection limit. Large blobs cause memory exhaustion during deserialization.
- **Recommended action**: Enforce hard cap (e.g., 50MB) before writing to database.

## Testing Findings

### T1 [Critical] No coverage threshold configured in pyproject.toml
- **Problem**: No `--cov-fail-under` or coverage config exists. Tests can be added without actually covering the critical paths.
- **Recommended action**: Add `addopts = "--cov=src/argus --cov-report=term-missing --cov-fail-under=80"` to pyproject.toml. Define 80%+ line coverage target for new modules.

### T2 [Critical] asyncio.wait_for() timeout enforcement test not planned
- **Problem**: NFR-4 timeout is security-critical but no test case covers it.
- **Recommended action**: Add mandatory test: `subdomain_scan_timeout=0.001` with mocked slow scanner → verify `TimeoutError` handling and result status.

### T3 [Major] Wildcard DNS deduplication test not planned
- **Problem**: Complex dedup logic with multiple edge cases (all same IP, partial wildcard, NXDOMAIN) not in test plan.
- **Recommended action**: Add parametrized wildcard detection tests with mocked DNS resolution.

### T4 [Major] DNS-first gating skip logic test not planned
- **Problem**: DNS failure → skip remaining modules not tested.
- **Recommended action**: Add test asserting remaining modules `assert_not_called()` when DNS returns no A/AAAA.

### T5 [Major] conftest.py lacks subdomain scan fixtures
- **Problem**: Only `sample_target` and `sample_options` exist. New fields not covered.
- **Recommended action**: Add `subdomain_scan_options` fixture to conftest.py.

### T6 [Major] Integration test mock strategy unclear — no DI
- **Problem**: `ScanCoordinator.__init__` directly instantiates scanners. No dependency injection = brittle mocks.
- **Recommended action**: `SubdomainScanCoordinator` should accept scanner dict via `__init__(scanners: dict | None = None)` for testability.

### T7 [Major] max_subdomains boundary value test not planned
- **Problem**: Cap behavior at boundaries (exactly at cap, over cap, min=1) not tested.
- **Recommended action**: Add parametrized test with `(10,50,10), (50,50,50), (51,50,50), (1,1,1)`.

### T8 [Minor] tests/unit/__init__.py and tests/integration/__init__.py may not exist
- **Recommended action**: Ensure __init__.py files exist in test subdirectories.

### T9 [Minor] Manual test pass criteria undefined
- **Recommended action**: Define concrete checklist (progress display, JSON key presence, concurrency equivalence, error message on invalid module).

## Adjacent Findings

### [Adjacent] S5 [Major] — overlaps with Infrastructure scope
No HTTP rate limiter in `MultiRateLimiter`. All HTTP-based subdomain modules (headers, discovery, webtech, security, graphql) run unthrottled. With 200 subdomains, HTTP volume could be order-of-magnitude higher than DNS volume.
- **Recommended action**: Add HTTP rate limiter entry to `MultiRateLimiter`.

### [Adjacent] T10 [Major] — overlaps with Security scope
SSRF validation at DNS resolution level needs dedicated tests. Verifying that DNS-resolved private IPs cause subdomain skip.
- *(Merged with S1/F3 — same root cause)*
