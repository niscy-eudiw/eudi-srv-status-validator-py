# Changelog

## [0.1.0]

### Added:
-  Initial Release

## [0.2.0]

_11 Nov 2026_

### Added
- `.github/workflows/`: `tests.yml`, `semgrep.yml`, `pipeline.yml` (image on `main`, `branch-*` and `v*` tags), `README.md`, and `.github/CODEOWNERS`.
- `.semgrep/security.yml` and `gitleaks/gitleaks.toml`.
- `Dockerfile` (non-root), `.dockerignore` and `docker-compose.yml`.
- Unit tests (99% coverage), run by `tests.yml` and `sonar.yml`; `requirements-dev.txt`, `pyproject.toml`.
- `install.md`: Docker and test instructions.
- Trust validator answers that accept a chain are cached per chain and `validation_context` (`trust_validator.cache_ttl`, default 300 s, never past the leaf's expiry).
- HTTP connections to the status list hosts and the trust validator are reused.

### Changed
- Workflow actions pinned to commit SHAs.
- `sonar.yml`: `sonarqube-scan-action` with coverage; pull requests scan the target branch, never the PR's code.
- Cache entries are keyed by URI and `validation_context`.
- The Status List cache is off by default (`cache.enabled`): a cached list reported revoked tokens as valid.
- `cache.default_ttl` is 300 s (was 12 h).

### Fixed
- A list trusted in one `validation_context` was served from the cache to another without a trust check.
- The token's `alg` is limited to asymmetric algorithms; `HS256`/`none` and other PyJWT rejections gave a 500 instead of a 502.
- The cache kept a token past its `exp` when `ttl` was longer.
- `idx: true` was accepted as index 1.
- Error messages had garbled non-ASCII characters (sources declared latin-1 but were UTF-8).
- `gitleaks.yml` pointed at a missing configuration file.
