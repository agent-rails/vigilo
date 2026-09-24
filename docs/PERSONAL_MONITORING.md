# Personal system monitoring

Vigilo reports activity for investigation; it does not decide that an event is malicious or block it. A file or process can have any name. Detection depends on the paths and event providers configured on the host.

## What works today

| Source | Observations | Limits |
|---|---|---|
| Linux and macOS file watcher | Creates, writes, removes, and renames for arbitrary names under configured `watch_paths`. Files found while a newly created subtree is being registered are reported as `reconciled_present`, without guessing whether they were created or written during the gap. Direct-file roots remain watched across atomic replacement. Missing roots are retried; watcher failures produce `collector_health` events. | Watches only configured roots. Symlink roots and subtrees are not followed; configure the resolved target path. It does not report reads or identify the process responsible. Transient files removed before reconciliation, exact operations during registration, and events lost to OS notification overflow may be missed. A coverage warning cannot reconstruct lost events. |
| Linux auditd (optional) | Rules for selected paths report a newly created file separately from a write-intent open on an existing file, plus deletes, renames, and actor PID, parent PID, UID, process name, and executable. A matching `execve`/`execveat` rule reports short-lived executions. Arbitrary names are included when a rule matches. | Vigilo reads audit records; it does not install rules. Coverage is only as broad as rules loaded on the host. The audit log must be readable. Configure architecture-specific rules and check event volume. Rotation, permission loss, sustained event volume, and other Linux distributions have not been validated on a live host. |
| Linux `/proc` and macOS process polling | Reports configured first-seen process inventory, identity changes while a PID remains present, and a small set of parent/child or OS-like-name/path clues. | Polling can miss a process that starts and exits between scans. Inventory requires `process_monitor.report_new_processes: true`; `alerter.min_severity_by_source.process` controls delivery, not collection. Name/path clues are triage only. |

The auditd examples in [`config.example.yaml`](../config.example.yaml) are examples, not rules Vigilo applies automatically. Match `arch=b64`/`arch=b32` to host ABIs before installing them. File-watch and process-polling gaps are not equivalent to kernel event coverage.

When the optional web server is enabled, `/healthz` reports daemon liveness separately from collection coverage. `coverage_status` starts as `unknown` and becomes `degraded` after a collector reports a gap. It remains degraded until restart because recovery does not establish that missed events were recovered. An `ok` liveness status is not proof of complete coverage.

## Verification

- `go test ./... -count=1` passed on the macOS development host and in a Linux Go 1.26 container.
- Linux amd64 and macOS arm64 builds passed.
- Linux auditd parser/tailer tests cover arbitrary paths, actor context, timestamps, create versus write-intent classification, read/write-intent flags, encoded values, relative paths, script/interpreter identity, incomplete groups, append-after-EOF, and replacement-inode rotation. These use synthetic audit records and temporary files.
- Filesystem tests cover direct files across atomic replacement, missing-root recovery, nested directories, and exclusions. Process tests cover live process observation on macOS/Linux, PID/start-time/executable identity changes, and parent lookup from one process snapshot.
- The CI release smoke test installs the archive and verifies systemd startup and alert delivery. The live auditd job installs temporary file and execution rules on an ephemeral Ubuntu runner and checks actor identity. It does not measure sustained event volume or cover a distribution matrix. Linux collector unit tests also pass in a Debian container; OrbStack's Linux kernel has no audit support, so the live auditd test must run on the hosted Ubuntu runner.
- No macOS Endpoint Security entitlement, consent, signed package, or runtime test was performed; macOS execution coverage remains polling-based.

## Remaining external gates

1. Extend live auditd acceptance beyond the Ubuntu CI runner: validate read/write semantics, rotation, permission loss, event volume, and supported Linux distributions/architectures.
2. Obtain Apple's Endpoint Security entitlement and build/test the signed, consented macOS provider. Until then, macOS execution observation remains polling-based and can miss short-lived processes.
3. Run a release-candidate host test for actual writes and executions under the documented selected paths, including provider loss and notification delivery.

See the [architecture and acceptance plan](PERSONAL_MONITORING_ARCHITECTURE.md) for the target coverage model and phased work.
