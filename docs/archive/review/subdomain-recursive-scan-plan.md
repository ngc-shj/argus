# Plan: Subdomain Recursive Scan

## Objective

Add a `--scan-subdomains` CLI option that automatically scans each subdomain discovered via CT logs (crt.sh) and/or subdomain enumeration, using selected scan modules (DNS, SSL, headers, etc.). This enables comprehensive attack surface analysis across all discovered subdomains from a single command.

## Requirements

### Functional Requirements

1. **FR-1**: After the initial scan discovers subdomains (via crt.sh or subdomain enumeration), automatically run selected scan modules against each discovered subdomain
2. **FR-2**: New CLI option `--scan-subdomains` to enable recursive subdomain scanning
3. **FR-3**: New CLI option `--subdomain-modules` to specify which modules to run against subdomains (default: `dns,ssl,headers`)
4. **FR-4**: New CLI option `--max-subdomain-concurrency` to control how many subdomains are scanned in parallel (default: 5)
5. **FR-5**: Display per-subdomain results in both table and JSON output formats
6. **FR-6**: Include subdomain scan results in HTML reports
7. **FR-7**: Include subdomain scan results in AI analysis when `--analyze` is enabled
8. **FR-8**: Save subdomain scan results to the database
9. **FR-9**: Emit a warning when `--scan-subdomains` is enabled but no subdomain discovery source (crtsh, subdomain_enum) is active

### Non-Functional Requirements

1. **NFR-1**: Respect existing rate limits to avoid overwhelming target infrastructure. Subdomain scanning phase must reuse the same rate limiters (DNS, HTTP) as the initial scan. Add HTTP rate limiter to `MultiRateLimiter` if missing
2. **NFR-2**: Each subdomain scan failure should not affect other subdomain scans (error isolation)
3. **NFR-3**: Progress indication for subdomain scanning phase (e.g., "Scanning subdomain 3/16..."). Progress total must be calculated after wildcard deduplication and cap, before the scan loop starts
4. **NFR-4**: Total scan time must be bounded by `subdomain_scan_timeout` enforced via `asyncio.wait_for()` — not just configured but actively enforced
5. **NFR-5**: Memory usage should remain reasonable even with many subdomains (lazy result processing)
6. **NFR-6**: Hard cap on maximum number of subdomains to scan (`max_subdomains: int = 50`, configurable 1-200) to prevent resource exhaustion from domains with thousands of subdomains
7. **NFR-7**: All subdomain ScanTarget objects must pass through the same SSRF validation (private IP, reserved ranges, forbidden domains) as the initial target. Additionally, resolved IPs must be validated against `BLOCKED_IP_RANGES` and `CLOUD_METADATA_IPS` after DNS resolution
8. **NFR-8**: Database blob size hard cap at 50MB; reject writes exceeding this limit with a warning

## Technical Approach

### Architecture

The feature extends the existing `ScanCoordinator` with a new post-processing phase. After the initial scan completes and subdomains are discovered, a new `SubdomainScanCoordinator` iterates over the discovered subdomains and runs lightweight scans using an `asyncio.Semaphore` for concurrency control.

```
CLI (--scan-subdomains)
  → ScanCoordinator.run_scan() [existing]
    → Phase 1: Initial scan (discovers subdomains via crt.sh/subdomain_enum)
    → Phase 2: NEW - SubdomainScanCoordinator
      → Step A: Collect & normalize subdomains from both sources
      → Step B: Apply max_subdomains cap (prioritize by cert_count desc)
      → Step C: DNS pre-resolution + SSRF IP validation (reject private IPs)
      → Step D: Wildcard deduplication (group by resolved IP)
      → Step E: Calculate final subdomain count for progress
      → Step F: For each subdomain (bounded concurrency, cached DNS):
        → DNS-first gating (use cached results, skip if no A/AAAA)
        → Run remaining selected modules
        → Store results in SubdomainScanResult
  → Aggregate results into ScanSession.subdomain_scan_results
```

### Key Design Decisions

1. **Separate coordinator class** (`SubdomainScanCoordinator`): Keeps the main coordinator clean and makes subdomain-specific logic testable in isolation
2. **Reuse existing scanners**: No new scanner modules needed — reuse DNS, SSL, ports, headers, etc. scanners with new ScanTarget per subdomain
3. **Bounded concurrency via semaphore**: Prevents resource exhaustion while allowing parallel scanning
4. **Per-subdomain result**: Each subdomain gets a `SubdomainScanResult`, aggregated into a list on the parent session
5. **Subdomain-safe module list**: Only modules that make sense per-subdomain are allowed (e.g., exclude whois/rdap/asn as they're domain-level, not subdomain-level)
6. **Hard subdomain cap**: Maximum 50 subdomains by default (configurable up to 200). When exceeded, prioritize by `cert_count = len(discovered_subdomain.certificate_ids)` descending. Subdomains from `subdomain_enum` (no cert info) receive `cert_count=0` and are deprioritized when cap is reached. Note: cert_count is a heuristic priority signal, not authoritative
7. **Unified DNS resolution with IP validation**: A single DNS pre-resolution pass serves three purposes: (a) SSRF IP validation against `BLOCKED_IP_RANGES`/`CLOUD_METADATA_IPS`, (b) wildcard deduplication by IP grouping, (c) cached results for DNS-first gating. This avoids double DNS queries and TOCTOU inconsistency
8. **DNS-first gating**: Uses cached `candidate.resolved_ips` from the pre-resolution step (not a fresh DNS query). If no A/AAAA records, skip remaining modules for that subdomain
9. **Explicit SSRF validation at both levels**: Domain-level via `ScanTarget(domain=subdomain)` constructor (catch `ValidationError` and skip with warning, not crash), and IP-level via post-resolution check against blocked ranges. Subdomains resolving to private/reserved IPs are excluded with a warning log
10. **Dependency injection for testability**: `SubdomainScanCoordinator.__init__(scanners: dict | None = None)` accepts optional scanner dict for test injection
11. **Graceful timeout behavior**: On `asyncio.wait_for` timeout, explicitly cancel all in-flight subdomain scan tasks (via `task.cancel()` for each), await their cancellation, and return partial results collected so far. Do not silently drop or corrupt already-collected results
12. **ALLOWED_SUBDOMAIN_MODULES location**: Define in `models/subdomain_scan.py` (not in `orchestration/`) to avoid circular imports between models and orchestration layers

### Allowed Subdomain Modules

| Module | Subdomain-safe | Reason |
|--------|---------------|--------|
| dns | Yes | A/AAAA records differ per subdomain |
| ssl | Yes | Different certificates per subdomain |
| ports | Yes (opt-in) | Different services; excluded from defaults due to high network load |
| headers | Yes | Different security headers per subdomain |
| webtech | Yes | Different tech stacks per subdomain |
| security | Yes | Different exposed files per subdomain |
| discovery | Yes | Different robots.txt etc. per subdomain |
| graphql | Yes | Different API endpoints per subdomain |
| js | No | High resource cost per subdomain; opt-in at domain level |
| takeover | No | Already uses subdomain data at session level |
| kev | No | Depends on vuln, which is excluded |
| wayback | No | Too slow per-subdomain; use at domain level |
| whois | No | Same registrar for all subdomains |
| rdap | No | Same network info |
| asn | No | Same ASN for most subdomains |
| crtsh | No | Already done at domain level |
| vuln | No | Depends on webtech (can be added post-scan) |
| email | No | SPF/DKIM/DMARC are domain-level |
| favicon | Yes (opt-in) | Could differ per subdomain; excluded from defaults |

### Normalized Subdomain Representation

Both `crtsh_result.discovered_subdomains` (type `list[DiscoveredSubdomain]` with `.certificate_ids`) and `subdomain_enum["subdomains"]` (type `list[str]`) are normalized into a common intermediate structure before processing:

```python
@dataclass
class SubdomainCandidate:
    domain: str
    cert_count: int = 0  # 0 for subdomain_enum sources
    source: str = "unknown"  # "crtsh" or "subdomain_enum"
    resolved_ips: list[str] = field(default_factory=list)  # populated during pre-resolution
```

## Pre-requisite: Fix IPv6 SSRF gap in target.py

Before implementing this feature, fix the pre-existing IPv6 SSRF gap in `validate_ip()` (amplified by increased target volume):
- Add `is_link_local` check for IPv6 addresses (currently only checked for IPv4)
- Add `is_multicast` and `is_unspecified` checks for IPv6 (currently only checked for IPv4)
- Add IPv4-mapped IPv6 address handling: when `IPv6Address(v).ipv4_mapped` is not None, extract the embedded IPv4 and run through the full IPv4 blocking logic (`BLOCKED_IP_RANGES`, `CLOUD_METADATA_IPS`, `is_link_local`, `is_multicast`, `is_unspecified`)

## Implementation Steps

### Step 1: Fix IPv6 SSRF gap (pre-requisite)

Update `src/argus/models/target.py`:
- Add an `elif isinstance(ip, IPv6Address):` block **in addition to** the existing generic `is_private or is_loopback or is_reserved` check (lines 95-96), not as a replacement. The generic check covers `is_loopback` for `::1`; the new block adds what's missing:
  - `ip.is_link_local` → reject
  - `ip.is_multicast` → reject
  - `ip.is_unspecified` → reject
  - `ip.ipv4_mapped is not None` → extract embedded IPv4 and run through the full IPv4 blocking logic (`BLOCKED_IP_RANGES`, `CLOUD_METADATA_IPS`, `is_link_local`, `is_multicast`, `is_unspecified`)

### Step 2: Add HTTP rate limiter

Update `src/argus/infrastructure/ratelimit.py`:
- Add `http` entry to `MultiRateLimiter` (e.g., 20 requests/second)
- Ensure `SubdomainScanCoordinator` acquires it before HTTP-based module scans

### Step 3: Add SubdomainScanResult model

Create `src/argus/models/subdomain_scan.py`:
- `ALLOWED_SUBDOMAIN_MODULES` constant (shared by both models and orchestration layers)
- `SubdomainCandidate` dataclass: normalized intermediate representation
- `SubdomainScanResult(BaseSchema)`: Per-subdomain result containing selected module results, status, errors, resolved_ips
- `SubdomainScanSummary(BaseSchema)`: Aggregated summary (total scanned, success/fail counts, key findings)

### Step 4: Add subdomain scan options to ScanOptions

Update `src/argus/models/target.py`:
- Add `subdomain_scan_enabled: bool = False`
- Add `subdomain_modules: list[str]` with default `["dns", "ssl", "headers"]` (ports excluded from default — opt-in)
- Add `max_subdomain_concurrency: int = 5` (with validation 1-20)
- Add `subdomain_scan_timeout: int = 300` (total timeout in seconds)
- Add `max_subdomains: int = 50` (hard cap, with validation 1-200)
- Add `field_validator` for `subdomain_modules` to reject unknown module names against `ALLOWED_SUBDOMAIN_MODULES` at the Pydantic model level (not just CLI)

### Step 5: Create SubdomainScanCoordinator

Create `src/argus/orchestration/subdomain_coordinator.py`:
- `SubdomainScanCoordinator` class with `__init__(self, scanners: dict | None = None)` for DI/testability
- Import `ALLOWED_SUBDOMAIN_MODULES` from `models/subdomain_scan.py` (do NOT redefine here)
- Method `async def scan_subdomains(candidates: list[SubdomainCandidate], modules: list[str], options: ScanOptions, progress_callback: Callable[[str, int, int], None] | None) -> list[SubdomainScanResult]`
- Processing flow:
  1. Validate modules against `ALLOWED_SUBDOMAIN_MODULES`; raise `ValueError` for unknown
  2. Apply `max_subdomains` cap: sort by `cert_count` descending, truncate
  3. DNS pre-resolution: resolve all subdomains, populate `resolved_ips`
  4. SSRF IP validation: check each resolved IP against `BLOCKED_IP_RANGES`/`CLOUD_METADATA_IPS`; exclude and warn for private IPs
  5. Wildcard deduplication: group by resolved IP set; select one representative per group
  6. Calculate final count; initialize progress
  7. Wrap scan loop in `asyncio.wait_for(timeout=subdomain_scan_timeout)`. On `TimeoutError`: explicitly cancel all in-flight tasks, await cancellation, return partial results collected so far (do not discard already-completed results)
  8. For each subdomain (via `asyncio.Semaphore(max_concurrency)`):
     - DNS-first gating: use cached resolution; skip if no A/AAAA
     - Run remaining modules with rate limiter acquisition
     - Store per-subdomain result with error isolation
- Uses `asyncio.Semaphore(max_concurrency)` for bounded parallelism
- Reuses the global rate limiters (DNS + HTTP) from `infrastructure/ratelimit.py`
- Error isolation: catch exceptions per subdomain, store error in result

### Step 6: Integrate into ScanCoordinator

Update `src/argus/orchestration/coordinator.py`:
- Add subdomain scanning phase after `_run_post_scans()` and before AI analysis
- Collect discovered subdomains from both `crtsh_result` and `subdomain_enum`
- Normalize into `list[SubdomainCandidate]` using the common intermediate structure
- Deduplicate by domain name
- Validate base-domain membership for `subdomain_enum` candidates (crtsh already enforces via `_normalize_domain()`, but subdomain_enum does not)
- Emit warning if `subdomain_scan_enabled=True` but subdomain list is empty (FR-9)
- Call `SubdomainScanCoordinator.scan_subdomains()`
- Store results in `session.subdomain_scan_results`

### Step 7: Update ScanSession model

Update `src/argus/models/scan.py`:
- Add `subdomain_scan_results: list[SubdomainScanResult] | None = None` to the `ScanSession` class body
- Do NOT relax `model_config = ConfigDict(extra="forbid")` — the field must be explicitly declared in the class definition

### Step 8: Add CLI options

Update `src/argus/cli/app.py`:
- Add `--scan-subdomains` flag
- Add `--subdomain-modules` option (comma-separated, validated against ALLOWED_SUBDOMAIN_MODULES)
- Add `--max-subdomain-concurrency` option
- Add `--max-subdomains` option
- Pass new options to `ScanOptions`

### Step 9: Add table formatter for subdomain results

Update `src/argus/cli/formatters/table.py`:
- Add `_format_subdomain_scan_results()` function
- Show summary table: subdomain, status, open ports, SSL grade, headers grade
- Show per-subdomain details on demand (top findings only)
- Integrate into `format_scan_result()`

### Step 10: Update JSON output

Update `ScanSession.to_json_dict()` or the Pydantic serialization to include subdomain scan results in JSON output.

### Step 11: Update HTML report

Update `src/argus/reports/html.py`:
- Add subdomain scan results section
- Summary table + expandable per-subdomain details
- **XSS prevention**: All subdomain-derived data (domain names, error messages, header values, discovered paths) must be HTML-escaped before inclusion — these are attacker-controlled strings

### Step 12: Update AI analysis prompt

Update `src/argus/ai/prompts/risk_assessment.py`:
- Include subdomain scan results in the AI analysis input
- Add subdomain-specific risk factors (e.g., inconsistent SSL configs, exposed services)
- **Token limit protection**: Summarize subdomain results before sending to AI (max 5 subdomains with full detail, remainder as summary statistics). Truncate total input to stay within model context limits
- **Prompt injection mitigation**: Subdomain-sourced content (HTTP headers, robots.txt, error messages) is attacker-controlled. Enclose in explicit data delimiters (e.g., `<scan_data>...</scan_data>`) and instruct the model to treat content within delimiters as untrusted data, not instructions

### Step 13: Update database schema

Update `src/argus/database/models.py` and `repository.py`:
- Store subdomain scan results as JSON blob
- Enforce 50MB hard cap on blob size in `repository.py`'s `update_from_session()` method, after `session.to_json_dict()` but before `record.results` assignment. Raise `ValueError` (not silent discard) if exceeded
- Log warning if blob exceeds 10MB

### Step 14: Add tests

Create tests:
- `tests/unit/test_subdomain_coordinator.py`: Unit tests for SubdomainScanCoordinator
- `tests/unit/test_subdomain_scan_model.py`: Model validation tests
- `tests/integration/test_subdomain_scan_flow.py`: Integration test with mocked scanners
- Ensure `tests/unit/__init__.py` and `tests/integration/__init__.py` exist

Update `tests/conftest.py`:
- Add `subdomain_scan_options` fixture with subdomain-specific defaults

Update `pyproject.toml`:
- Add `addopts` key to the **existing** `[tool.pytest.ini_options]` section (do NOT create a duplicate section): `addopts = "--cov=src/argus --cov-report=term-missing --cov-fail-under=80"`

## Testing Strategy

### Unit Tests — SubdomainScanCoordinator

| Test case | Priority |
|-----------|----------|
| Concurrency control: verify semaphore limits parallel execution | Must |
| Error isolation: one subdomain failure doesn't affect others | Must |
| Module validation: reject unknown module names with ValueError | Must |
| **Timeout enforcement**: `subdomain_scan_timeout=0.001` with slow mock → verify: (a) `TimeoutError` is caught, (b) partial results already collected are returned, (c) in-flight tasks are cancelled | Must |
| **Wildcard DNS dedup**: all-same-IP → scan only 1; partial-same-IP → correct grouping; NXDOMAIN handling | Must |
| **DNS-first gating**: no A/AAAA → remaining modules `assert_not_called()` | Must |
| **DNS failure exception**: DNS module throws → remaining modules skipped gracefully | Must |
| **max_subdomains boundary values**: parametrized `(10,50,10), (50,50,50), (51,50,50), (1,1,1)` | Must |
| **SSRF IP validation**: DNS resolves to 169.254.169.254 → subdomain skipped with warning | Must |
| **IPv6 SSRF**: DNS resolves to fe80::1 or ::ffff:10.0.0.1 → subdomain skipped | Must |
| Progress callback: receives correct (subdomain, current, total) after dedup | Should |
| Subdomain source normalization: cert_count=0 for subdomain_enum sources | Should |

### Unit Tests — validate_ip() IPv6 fix (Step 1)

| Test case | Priority |
|-----------|----------|
| `ScanTarget(ip_address="fe80::1")` → rejected (IPv6 link-local) | Must |
| `ScanTarget(ip_address="::ffff:169.254.169.254")` → rejected (IPv4-mapped cloud metadata) | Must |
| `ScanTarget(ip_address="::ffff:10.0.0.1")` → rejected (IPv4-mapped private) | Must |
| `ScanTarget(ip_address="::ffff:c0a8:0101")` → rejected (all-hex IPv4-mapped private) | Must |
| `ScanTarget(ip_address="ff02::1")` → rejected (IPv6 multicast) | Must |
| `ScanTarget(ip_address="::")` → rejected (IPv6 unspecified) | Must |

### Unit Tests — Model Validation

| Test case | Priority |
|-----------|----------|
| SubdomainScanResult serialization and default values | Must |
| ScanOptions.subdomain_modules rejects unknown module name | Must |
| ScanOptions.max_subdomains boundary validation (1-200, model-level rejection for out-of-range) | Must |
| SubdomainCandidate normalization: `cert_count = len(certificate_ids)` for crtsh, `cert_count=0` for subdomain_enum | Must |

### Integration Tests

| Test case | Priority |
|-----------|----------|
| Full scan flow with mocked scanners returning subdomain data | Must |
| Subdomain deduplication from crtsh + subdomain_enum combined | Must |
| Rate limiting respected during subdomain scanning phase | Should |
| Empty subdomain list with subdomain_scan_enabled → warning emitted | Should |

Mock strategy: `SubdomainScanCoordinator` accepts `scanners: dict` via `__init__()` for clean DI. No `unittest.mock.patch` of internal paths needed.

### Manual Testing Checklist

- [ ] Table output shows "Scanning subdomain X/Y..." progress
- [ ] JSON output contains `subdomain_scan_results` key with >= 1 entry
- [ ] `--max-subdomain-concurrency 1` and `5` produce equivalent results
- [ ] `--subdomain-modules invalid_module` exits with clear error message
- [ ] `--scan-subdomains` without crtsh emits warning about no subdomain sources
- [ ] HTML report includes subdomain scan results section

## Considerations & Constraints

1. **Rate limiting**: Scanning many subdomains can trigger rate limits or security controls. The semaphore-based concurrency limit, global rate limiters (DNS + new HTTP limiter), and the hard subdomain cap mitigate this.
2. **Scope control**: Only scan subdomains belonging to the original base domain (already enforced by crt.sh scanner's `_normalize_domain()`).
3. **Timeout**: A global timeout actively enforced via `asyncio.wait_for()` prevents runaway scans when many subdomains are unreachable.
4. **DNS resolution**: Single pre-resolution pass serves SSRF validation, wildcard dedup, and DNS-first gating. Cached results avoid double resolution and TOCTOU inconsistency.
5. **Wildcard subdomains**: Pre-resolution groups subdomains by resolved IP. If wildcard detected (many → same IP), only one representative per unique IP is scanned.
6. **SSRF protections**: Two-level validation: (1) domain-level via `ScanTarget(domain=)` constructor, (2) IP-level via post-resolution check against `BLOCKED_IP_RANGES`/`CLOUD_METADATA_IPS`/`is_link_local`. IPv6 and IPv4-mapped IPv6 covered.
7. **Database size**: Store as JSON blob with 50MB hard cap. Log warning at 10MB.
8. **Subdomain sources**: Collected from `crtsh_result.discovered_subdomains` and `subdomain_enum["subdomains"]`. Normalized into `SubdomainCandidate` with `cert_count` for prioritization.
9. **CLI module validation**: Validated at both CLI parse time (user-friendly error) and Pydantic model level (programmatic safety) against `ALLOWED_SUBDOMAIN_MODULES`.
10. **Ports module**: Excluded from default `subdomain_modules` due to high network load (50 subdomains × 100 ports = 5000 probes). Opt-in via `--subdomain-modules dns,ssl,ports,headers`.
