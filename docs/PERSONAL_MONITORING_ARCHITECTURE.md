# Personal-system monitoring architecture

This document records the target architecture and acceptance plan; it is not a claim that every phase is implemented. For verified current behavior and outstanding host gates, see [personal monitoring coverage](PERSONAL_MONITORING.md).

## Purpose and coverage contract

Vigilo reports observable changes so a person can investigate unexpected activity. It does not decide that an event is malicious, prevent it, or guarantee that a host is clean. A filename or process name may be arbitrary; name-based rules are supplemental triage signals and must never be the only way an event is collected.

Coverage is defined by the locations and providers the user selects, plus the health state of those providers. Vigilo must say which roots and event sources are active, which are unavailable, and where coverage is degraded. “Running” must not imply “watching the whole system.” Existing `watch_paths`, `exclude_paths`, `auditd_log_path`, and `alerter.min_severity_by_source` remain supported while the configuration grows; collection enablement and alert thresholds should become separate settings.

The current file watcher reports create, write, remove, and rename observations under configured paths for arbitrary names. It has no process attribution and may lose coverage when a root cannot be watched or the OS notification queue overflows. Linux auditd can supply actor context for events covered by installed rules and event-driven execution observations. Linux `/proc` and macOS `ps` polling can report newly observed processes that survive a scan interval, but can miss short-lived executions. The polling implementations and filesystem watcher are fallback sources, not equivalent substitutes for kernel event providers.

## Provider strategy

### Linux

Use auditd as the first supported event-driven provider for executions and user-selected filesystem roots. Separate privileged rule installation from the unprivileged Vigilo daemon. Ship auditable rule profiles with architecture-specific syscall selectors, explain the resulting scope and event volume, and verify which rules are actually loaded. Keep `/proc` polling as an optional, lower-confidence inventory fallback; report that it can miss processes between scans.

Before claiming coverage, harden the audit reader: associate records by audit serial, distinguish reads from writes using syscall flags, preserve correct create/delete/rename semantics, handle partial groups and log rotation/truncation, and expose parse/read/loss failures. Do not depend on eBPF for the initial supported path. Evaluate it later only if auditd’s distribution compatibility, performance, or coverage fails acceptance; eBPF adds kernel/BTF compatibility and elevated capability and packaging requirements.

### macOS

The target event-driven provider is Apple Endpoint Security for execution events and file events with actor identity. Treat its entitlement, signing/notarization, installation, and user-consent path as release requirements. The provider must report permission denial, client loss, and reconnect failure as degraded coverage.

Until that distribution path is available and tested, retain configured-root filesystem notifications and process polling only as an explicitly degraded fallback. It cannot claim short-lived execution coverage or reliable process-to-file attribution. Do not silently describe the fallback as equivalent to Endpoint Security.

## Event and health model

Normalize provider observations into the existing event stream while adding provider identity and stable event semantics. An event should contain:

- event time, source/provider, action, resource, severity, and a concise evidence detail;
- actor identity when the provider supplies it: PID, parent PID, UID/user, process name, and executable path;
- an indication of attribution confidence or unavailable identity, rather than implying that missing identity means no actor.

Actions should distinguish execution, create, write, delete/remove, rename, and read where the provider can prove them. Do not label an `open` as a write without checking the access flags. Preserve arbitrary names and paths; heuristics may add a triage annotation but must not rewrite the underlying observation.

Expose per-provider state such as `starting`, `healthy`, `degraded`, `unavailable`, and `stopped`, together with configured scope, last successful event/read time, watched-root count, and counters for queue pressure, dropped events, parse failures, permission failures, and provider restarts. Startup logs and health/metrics endpoints should show effective coverage. A collector that cannot watch a requested root or read its event source must not report healthy coverage for it.

## Privacy, volume, and delivery

Do not retain command-line arguments or file contents by default; both commonly contain credentials or private data. Bound and sanitize resource/detail strings before persistence and outbound delivery. Keep event retention finite and the local database readable only by the Vigilo service account. Avoid adding hashes or file snapshots without an explicit user choice and a documented privacy tradeoff.

Process execution monitoring can produce high event volume, while a broad home-directory watch can generate large bursts during package installs and builds. Make scope and exclusions user-controlled, explain the noise implications of `info` alerts, and keep the collection policy independent from alert thresholds. Use a bounded ingestion path with observable queue depth and drop counts. Coalesce repetitive writes to the same path over a short window only if this cannot hide create, delete, rename, or first-execution evidence. Persist observations before attempting notification; delivery failures and dropped alerts must be visible. Never silently block a kernel/audit reader indefinitely on a slow webhook.

Alerts should state what was observed, where, by which provider, and which actor fields are known. They should call an event an observation or triage signal, not a malware verdict. If no notification channel is configured, surface that fact in startup and health status.

## Phased implementation and acceptance

### Phase 1: contracts and configuration

Keep existing YAML compatible. Add explicit provider and scope controls, separate collection from alert policy, validate paths and provider settings, and report the effective coverage at startup. Test legacy configuration fixtures, invalid configuration, arbitrary filenames/process names, path spaces, exclusions, and source-specific alert thresholds.

### Phase 2: Linux event-driven coverage

Harden audit parsing and tailing, add rule profiles for selected paths and execution events, and implement provider health counters. In a disposable Linux environment with audit support, verify create, overwrite, rename, and delete of arbitrary filenames and execution of an arbitrary-named binary shorter-lived than the polling interval. Assert actor PID/PPID/UID/executable where available, no argv retention, correct action semantics, visible behavior on rotation/permission loss/provider stop, and bounded queue/drop behavior during package-install-like bursts. Measure event rate and resource cost for documented representative workloads.

### Phase 3: macOS event-driven coverage

Prototype the Endpoint Security client and distribution path before promising full macOS coverage. On a supported macOS release, test a signed/notarized install and consent flow, short-lived arbitrary-named execution, create/overwrite/rename/delete with actor identity where exposed, and provider loss or revoked permission. Until the entitlement and runtime gates pass, acceptance is limited to accurately reporting degraded fallback coverage.

### Phase 4: shared user experience and resilience

Expose provider health and effective scope in health/metrics and the user-facing status surface. Exercise alert formatting, event retention, privacy bounds, alert delivery failure, collector restart, and queue saturation. Run cross-platform tests, race tests, Linux and macOS builds, and end-to-end tests proving that selected roots and arbitrary names behave as documented. Re-run resource and noise evaluation against the release candidate and publish its scope and limitations.

### Phase 5: security review and release

Have a security architect review privilege boundaries, rule tampering, path/symlink handling, event spoofing, suppression behavior, volume denial-of-service, secret leakage, local-store permissions, notification failures, and provider-health integrity. Release documentation must distinguish tested Linux auditd coverage from macOS Endpoint Security coverage and must not claim platform-wide monitoring where runtime acceptance is absent.

## External gates and limits

Linux runtime acceptance requires a host or disposable VM with audit support and permission to install and inspect audit rules; container parser tests alone do not prove kernel event coverage. Distribution coverage requires testing the supported architectures and audit implementations.

macOS full coverage depends on Apple Endpoint Security entitlement approval, the signed/notarized extension or service packaging, and user consent on the supported OS versions. These gates cannot be established by a cross-compile or unit test. If they are not met, Vigilo must describe macOS execution coverage as polling-based and incomplete.

Neither provider protects against a compromised kernel or a sufficiently privileged attacker who can stop Vigilo, alter its configuration, or tamper with local event storage. Vigilo is an observation and notification tool; a missing event is not proof that no change occurred.
