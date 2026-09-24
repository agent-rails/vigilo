# Changelog

## Unreleased

### Changes

- Add a personal login-user configuration with notifications for watched-path changes and first-seen processes.
- Add per-user systemd and macOS LaunchAgent setup, with owner-only config, state, and notification-secret files.
- Add live Linux auditd acceptance and per-user service end-to-end checks to CI; add a macOS LaunchAgent end-to-end check.

### Limits

- Linux auditd behavior and event volume still require validation across supported distributions and representative workloads.
- macOS process monitoring remains polling-based until Apple grants the Endpoint Security entitlement and the signed provider is implemented and tested.
- File coverage is limited to configured paths; no provider prevents a sufficiently privileged attacker from disabling or tampering with Vigilo.

## v0.2.1

### Changes

- Watch nested directory trees created after startup, and emit remove/rename events for watched paths.
- Keep terminal file events (`remove`/`rename`) from being suppressed by a prior write; shorten dedup suppression after total alert-delivery failure to a 30-second backoff.
- Report malformed analyst output and failed event retrieval as incomplete scans, not clean scans; preserve evidence indices through event compaction.
- Re-run the immediate-tier evaluation on the release candidate. Results and scope limits are recorded in `docs/reports/v0.2.1-evaluation.md`.

### Limits

Filesystem reads remain invisible to the default collector. Recursive directory walks are synchronous and can delay event handling; the daemon cannot reconstruct events lost to inotify queue overflow. File events do not identify the process, and rename events are not correlated with creates. The analyst tier remains unevaluated for detection quality and prompt-injection resistance. The local Docker evaluation is development evidence, not production-validator evidence.

## v0.2.0

### Upgrade notes

- HTTP MCP now requires a bearer token by default. Set `VIGILO_MCP_TOKEN` on the daemon and analyst client before upgrading. An explicit `mcp_allow_unauthenticated: true` opt-out exists for isolated environments; unauthenticated remote access exposes event data.
- Linux release archives install their bundled binary with `sudo bash deploy/install.sh`; no Go toolchain is required. Existing configuration and environment files are preserved. The installer does not start or restart the service. Source installs require Go 1.25+.
- Use authenticated HTTP MCP for an analyst querying a systemd service. With stdio and no input, the daemon keeps collecting and alerting while reporting MCP unavailable. Transport failure does not automatically restart the transport.

### Changes

- Collection and immediate alerts survive MCP transport closure. Stdio uses the daemon's shutdown context, and MCP availability is visible in health and metrics output.
- Individual files in `watch_paths` are registered correctly. The default watcher handles create/write events; it does not report reads or attribute changes to a process.
- Optional npm and Terraform supply-chain checks, plus configurable network indicators. These are heuristics and indicators, not proof of compromise.
- HTTP MCP authentication, browser-origin rejection, relative SSE endpoints, and graceful listener shutdown.
- Correct handling of an explicitly zero alert cooldown.
- Reproducible evaluation runners with trigger-failure propagation and event-store measurements after checkpointing a copied SQLite store. Storage results include page resolution and are workload-dependent; they are not a throughput benchmark.
- Updated installer, release instructions, and coverage documentation. Missing example watch directories no longer prevent the systemd unit from starting.

### Limits

Process and network polling can miss brief activity. Audit-log ingestion is opt-in and depends on Linux audit rules and permissions. Alert delivery and LLM analysis are not guaranteed. The daemon does not prevent attacks. See SECURITY.md for deployment guidance and coverage limits.
