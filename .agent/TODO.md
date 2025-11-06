# OneScan Fingerprint Format Merge TODO

- Implement save-time merge of same `dataSource+field+method` into one matcher with `content` list and `condition: and`.
- Aggregate entries by name so related matchers live under one item.
- Verify loader supports list `content` and `condition` (FpManager already handles).
- Update bundled example YAML for Swagger-UI to demonstrate target format.
- Add samples showing before/after conversion.
- Optional: add conversion utility later if needed.

