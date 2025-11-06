# Upgrade Guide: 2.2.0 → 2.3.0 (Montoya API)

This guide explains how to upgrade OneScan from v2.2.0 (legacy Burp Extender API) to v2.3.0 (Montoya API).

## Overview
- Core integration migrates to Burp Montoya API while retaining safe fallbacks to legacy callbacks where necessary.
- UI, HTTP, proxy, and logging paths prefer Montoya; legacy interfaces remain only for interop during transition.

## Requirements
- Burp Suite that supports Montoya API (tested against `montoya-api:2025.5`).
- Java 17 (unchanged).

## What’s Changed
- Entry point implements Montoya `BurpExtension#initialize(MontoyaApi)`; minimal `extension.Extension` stubs added.
- HTTP requests use `montoya.http().sendRequest(...)` with Montoya `HttpRequest` builders.
- Suite tab, context menu, message editors register/create via Montoya UI API with fallback.
- Proxy response handler uses Montoya API.
- Logging routes via Montoya logging through an adapter.
- Version bumped to `2.3.0` in `pom.xml` and `Constants.PLUGIN_VERSION`.

## Configuration Compatibility
- Existing `config.json` is auto-upgraded on first run:
  - `version` is updated to `2.3.0`.
  - Legacy keys migrated: `white-host` → `host-allowlist`, `black-host` → `host-blocklist`, `exclude-headers` → `remove-headers`.
  - Wordlist directories renamed if present.
- Backup logic applies for `0.x` → `1.x` upgrades (unchanged from earlier versions).
- Fingerprint YAML (`fp_config.yaml`) is initialized or reused in the working directory.

## Working Directory
- Preferred: a `OneScan` directory next to the plugin JAR.
- Fallback: `${USER_HOME}/.config/OneScan/`.
- In v2.3.0, path handling appends a separator when a custom work dir is used to prevent path join issues.

## Upgrade Steps
1. Build or download `OneScan-v2.3.0.jar`.
2. In Burp Suite: `Extender → Extensions → Add → Select File → Next`.
3. Ensure your previous `OneScan` working directory is preserved next to the JAR or under `${USER_HOME}/.config/OneScan/`.
4. Start Burp; OneScan initializes and upgrades config automatically.

## Rollback
- If needed, revert to v2.2.0:
  - Remove the v2.3.0 JAR, add `OneScan-v2.2.0.jar`.
  - Configuration keys migrated for v2.3.0 will remain; legacy code paths tolerate unknown keys.
  - Your data (wordlists/fingerprints) is preserved.

## Manual Verification Checklist
- Suite tab appears and shows DataBoard/Fingerprint/Config tabs.
- Context menu includes “Send to OneScan” and payload submenu when ≥2 payload lists exist.
- Editors display request/response; interaction feels consistent with v2.2.0.
- Proxy response handler captures responses when “Listen Proxy” is enabled.
- Configuration panel loads/saves; wordlist directories present; filters work.

## Known Notes
- Some legacy interfaces remain for interop; they are guarded by runtime fallbacks.
- Montoya factories aren’t available outside the Burp runtime; tests skip accordingly.

## Support
If you encounter issues, enable `Constants.DEBUG = true` and share logs. Use `scripts/compatibility-test.sh` to verify jar build outputs.
