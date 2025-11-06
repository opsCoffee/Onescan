# Changelog

All notable changes to this project will be documented in this file.

## [2.3.0] - 2025-11-06

### Added
- Migrate core to Burp Montoya API:
  - Implement `BurpExtension#initialize(MontoyaApi)` entrypoint.
  - Use Montoya `Http.sendRequest(...)` for HTTP, with legacy fallback during transition.
  - Register suite tab and context menu via Montoya UI API (with fallback).
  - Register proxy response handler via Montoya Proxy API (with fallback).
- Montoya message editors (request/response) integrated into UI with graceful fallback.
- Config compatibility and upgrade logic verified; test added for v2.2.0 → v2.3.0 upgrade.
- Logging now routed via Montoya logging (adapter) when available.
- Integration and unit tests updated/added (encoding, Montoya factories, config upgrade).
- Regression helper script `scripts/compatibility-test.sh`.

### Changed
- Bump version to 2.3.0.
- Update README, CLAUDE.md to reflect Montoya migration and new version.

### Notes
- Some legacy interfaces remain for interop during transition; they are protected by fallbacks.

