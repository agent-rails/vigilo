# Design

The "why" document. `README.md` is how to run vigilo; `SECURITY.md` is the deployment and disclosure policy; `docs/THREAT_MODEL.md` is what it defends and, more importantly, what it does not. This is the reasoning behind the shape it took and the alternatives weighed against it.

## The thesis

A validator, signer or bridge node is a host where the thing worth stealing is a file, and the theft is irreversible the moment it succeeds. There is no chargeback on a drained hot wallet. That asymmetry sets the design goal: not "block the attacker" — a userspace daemon cannot — but **shorten the interval between the attacker touching a key and a human knowing about it**, and make that interval short enough to matter while a transaction is still in flight rather than after settlement.

Two consequences follow, and they drive nearly every other decision:

- **Vigilo observes; it never intervenes.** No syscall interposition, no LD_PRELOAD, no blocking hook in front of a file open. The daemon runs as an unprivileged user with an empty capability set (`deploy/vigilo.service`: `CapabilityBoundingSet=`, `NoNewPrivileges=yes`) and reads `/proc` and inotify. A monitoring tool that can block is a monitoring tool that can take a validator offline when its rules are wrong, and an unavailable signer is itself an incident.
- **The alert path cannot depend on a model being reachable.** An LLM is the right tool for correlating a sequence across five minutes and three hosts. It is the wrong tool to stand between a keystore write and a phone buzzing: it adds an API round trip, a bill, a rate limit and a third-party availability dependency to the one path that has to work during an active compromise. This is not hypothetical — the evaluation in `eval/` ran its latency and false-positive passes with the analyst tier out of scope entirely because of an API billing problem, and the immediate tier was measured and working throughout.

## The shape

```
Monitored host (validator / signer / bridge node)
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  FileWatcher   (fsnotify / inotify)  ─┐                                  │
│  ProcessWatcher (/proc poll)          │                                  │
│  NetworkWatcher (/proc/net/tcp poll)  ├─► SuppressMatcher ─► event bus   │
│  SupplyChainGuard (manifest scan)     │                      (chan, 512) │
│  AuditdWatcher  (audit.log, opt-in)  ─┘                          │       │
│                                                                  ▼       │
│                                              ┌──────── drain goroutine   │
│                                              │                           │
│                    ┌─────────────────────────┼───────────────┐           │
│                    ▼                         ▼               ▼           │
│            SQLite buffer            Dispatcher          web.Broadcaster  │
│            (WAL, 24h retention)     (tier 1, ~1s)       (SSE dashboard)  │
│                    │                         │                           │
│                    ▼                         ▼                           │
│            MCP server                Slack / Telegram / SMTP /           │
│            (stdio | SSE+token)       webhook / syslog(CEF)               │
└────────────────────┼─────────────────────────────────────────────────────┘
                     │ MCP (Bearer, over Tailscale/WireGuard)
                     ▼
        vigilo-agent (TypeScript, Claude)   ── tier 2, every ~5 min
        fetch events → correlate → post signals to Slack
```

Collection is Linux-first by construction: `ProcessWatcher` and `NetworkWatcher` read `/proc` and `/proc/net/tcp`, and the `auditd` collector tails the kernel audit log. Build-tagged macOS equivalents (`process_darwin.go`, `network_darwin.go`, shelling out to `ps`/`netstat`) exist so the daemon builds and runs for development; they are not the target deployment and are not measured.

## Why two tiers rather than one

The two tiers are not redundancy. They answer different questions and fail independently.

**Tier 1 (`internal/alerter`) answers "did something touch a key just now?"** It is a severity threshold over single events — no state, no model, no correlation. Measured in the isolated eval stack (`eval/docker/`, reproduced via `eval/scripts/run_evaluation.py`) at commit `14015e2`, n=10 per chain, median / p95 detection-to-alert latency:

| Chain | Median | p95 | Mechanism |
|---|---|---|---|
| `keystore_write` | 87.8 ms | 282.5 ms | fsnotify (event-driven) |
| `env_write` | 53.9 ms | 60.4 ms | fsnotify (event-driven) |
| `suspicious_outbound` | 623.1 ms | 1013.0 ms | `/proc/net/tcp` poll, `poll_interval: 1s` |

The network number is dominated by the poll interval and is only meaningful stated alongside it. At the shipped default of `poll_interval: 5s` the same chain's latency scales with that interval; it has not been measured at 5s. `14015e2` predates #27, so these three chains are the only ones measured: the `remove` and `rename` file events added there have no latency figure, and nothing in this table is a statement about them.

**Tier 2 (`agent/`) answers "do the last five minutes add up to an attack?"** A shell spawned from `node` is suspicious; a shell spawned from `node`, followed by a read of `.env`, followed by an outbound connection, is a story. Expressing that as static rules means enumerating sequences an attacker has not used yet. This is the one part of the system where the open-ended, "I have not seen this exact pattern before" judgment of a model genuinely earns its cost — and it is deliberately kept off the fast path, out of the daemon process, and out of the daemon's language, so that a failure of the agent (API outage, bad key, malformed model output) degrades tier 2 to silence while tier 1 keeps firing.

Following the framing in Anthropic's *Building effective agents*: the analyst is a **fixed workflow with validation gates**, not an autonomous agent loop. It runs on a cron, makes a bounded number of Claude calls (one, plus up to two corrective re-asks), parses a structured result, and posts. It directs no tool use of its own and controls no branching. That is a deliberate ceiling, discussed further under "excessive agency" in the threat model.

## Why SQLite as the buffer

The buffer has an unglamorous job: absorb bursts, survive a restart, answer "what happened between T1 and T2" fast enough for a tool call, and cost nothing when idle.

SQLite in WAL mode (`internal/buffer/sqlite.go`) fits because:

- **It is a file, not a service.** No second process to supervise, no port, no credential, no network trust boundary. The event store is the single most sensitive artefact vigilo produces — it is a map of where the keys live on this host — and keeping it a local file under a dedicated user is the cheapest containment available.
- **Single-writer is a feature here.** There is exactly one writer (the drain goroutine), so `db.SetMaxOpenConns(1)` makes the concurrency model trivially correct rather than merely fast.
- **The cost is measured and small.** 273 +/- 137 B/event marginal, measured after a WAL checkpoint at commit `0eef911`. The `+/-` is not decoration: SQLite grows the file in whole 4096 B pages, so the resolution of this measurement is one page divided by the 30 events it saw, and `run_overhead.py` emits a `precision_note` telling the reader to treat it as an order of magnitude rather than a byte count. The checkpoint matters too: an earlier measurement of the same thing reported a per-event figure roughly a hundred times larger because it counted WAL churn as stored data. Daemon overhead on the same run: 0.19% CPU / 12.83 MiB idle, 1.7% CPU / 12.63 MiB under load — and those numbers carry less precision than their digits suggest, for three reasons stated below.
- **Retention is a `DELETE`, not a compaction strategy.** A background loop prunes events older than `buffer_retention_hours` (default 24) once an hour.

What those overhead numbers actually measure, since the digits overstate it. `sample_resources` parses `docker stats` against the eval container, so (1) it is a container measurement, not a systemd unit on a validator — the daemon is that container's only long-lived process, but the figure is still the container's; (2) the memory figure is `docker stats` `MemUsage`, which is container memory, not the daemon's RSS; (3) `docker stats` CPU% is `(cpuDelta / systemDelta) * onlineCPUs * 100` (docker/cli, `stats_helpers.go`), so 100% means one core fully busy, not the whole machine — the number is only comparable against another reading taken the same way. The medians come from 1-second samples over a 30 s idle window and a load window bounded by how long the trigger chains take. In the run quoted above the load-window memory median (12.63 MiB) came out *below* the idle median (12.83 MiB), which is the honest bound on this measurement's precision: at this sample count and granularity it supports "roughly 12–13 MiB and a fraction of one core", not four significant figures. `eval/.gitignore` excludes `results/`, so the run artefact is not in the repository and the commit is the only provenance.

Alternatives weighed: an in-memory ring buffer loses everything on the restart that a compromise is most likely to cause; flat JSONL makes "high-severity events since T" a full scan; Postgres re-introduces a service, a port and a credential to protect the thing that is supposed to be reducing attack surface. Nothing in the measured workload justifies any of them.

What SQLite costs: queries serialise behind one connection, and there is no cross-host store. Multi-host correlation happens in the agent, by fan-out over N daemons, not in a shared database.

## Why MCP rather than the agent reading the database directly

The agent could open `events.db` read-only and skip a network hop. It does not, for reasons that are about boundaries rather than convenience:

- **The agent is usually not on the monitored host.** The intended topology (`README.md`, multi-server section) is N daemons on N validators, one agent on a central host, reachable over a Tailscale/WireGuard interface. "Read the file" does not cross that boundary; a protocol does.
- **A tool call is a narrower contract than a file handle.** The six registered tools (`internal/mcp/server.go`) expose filtered, capped reads — `since`, `severity`, `limit` clamped to 1000 — and nothing else. There is no tool that writes, deletes, reconfigures or suppresses. Handing over the database file hands over the whole schema and any future column in it.
- **One protocol, many clients.** Because the daemon speaks MCP rather than a bespoke API, any MCP-capable client — Claude Desktop included — can investigate a host interactively without vigilo shipping a second integration.
- **It creates exactly one place to put authentication.** This is also the cost: an HTTP listener that returns "where are the keystores on this host" needs a real auth story, and getting that right took several corrections (below).

## What was tried and corrected

These are the course corrections that taught something. Each is in the git history; each is here because the wrong version looked reasonable.

**A guard that would have been silently bypassed.** The obvious way to authenticate the SSE transport is to configure an `*http.Server` with a wrapped handler and hand it to the library. `SSEServer.Start` overwrites any configured server with one whose handler is the bare SSE server — the wrapper would have been discarded and the event buffer served unauthenticated, with no error and no failing test. `ServeSSE` now constructs its own listener (`internal/mcp/server.go`). The lesson generalises: a security control that lives one layer below an API you do not own needs an end-to-end test against the real listener, not a unit test of the middleware. `test/e2e/mcp_auth_test.go` asserts through a running daemon, and treats a `400 Missing sessionId` on a *correct* token as the proof that the request reached the MCP server rather than merely escaping the middleware.

**An omitted secret is not consent.** Earlier, `mcp_transport: http` with no token simply served unauthenticated. Now the daemon refuses to start, unless the operator sets `mcp_allow_unauthenticated: true`, which logs a WARN at startup. The escape hatch is deliberate — a hard break with no way out is how operators end up pinned to an old version — but it has to be stated rather than inferred.

**Zero is a real value.** `alerter.New` treated `Cooldown == 0` as "unset" and substituted 15 minutes, so a config that said `signal_cooldown: 0s` got 15 minutes and no indication otherwise. Only a negative duration now requests the default. This was found by the evaluation harness, not by a test: a measurement that needed "no cooldown" silently got 15 minutes and produced nonsense.

**The README described coverage the collector does not have.** The detection table listed "private key / keystore file **read**" as an immediate-tier signal. fsnotify's inotify backend subscribes to `IN_CREATE | IN_MODIFY | IN_ATTRIB | IN_MOVED_* | IN_DELETE*` and never to `IN_ACCESS`; reads are not observable through this collector at all. Verified live: `cat` on a watched keystore file produces no event; a write to the same path alerts. Reads require the opt-in `auditd` collector. The evaluation was rewritten around write-based chains rather than around what the table implied.

**A `watch_paths` entry naming a single file was silently never watched.** `addRecursive` walked directories and skipped non-directory entries, so `/app/.env` — the exact form `config.example.yaml` recommends — was accepted, logged as watched, and observed nothing. Silent non-coverage is the characteristic failure of this whole class of tool, which is also why `expandPath` exists: a config saying `~/.ssh` used to be passed to the OS verbatim and match nothing.

**No implicit `$HOME` default for the supply-chain guard.** The shipped unit creates the service account with `--no-create-home`, so a defaulted root would resolve to a non-existent path and every scan would inspect zero files while reporting success. Roots are now required, and roots that do not resolve are dropped with an ERROR and the guard refuses to start rather than scanning nothing.

**Shutdown ordering is a correctness problem, not tidiness.** Every collector must stop before `close(events)`; an in-flight send on a closed channel panics the daemon, and under `Restart=always` that is a crash loop that also skips `store.Close()` and loses buffered events. Collector sends are `select`-ed against a stop channel for the same reason. The ordering narrows the window rather than proving it shut — `stopCollectors()` signals but does not wait, so a goroutine whose send and stop cases are both ready can still take the send. Closing that properly needs a `WaitGroup` over the collectors, which is not there yet.

**Measuring the wrong thing.** The event-store cost was first reported at roughly 27 KB/event. That was WAL churn counted as stored data. Measured after a checkpoint the marginal cost is 273 +/- 137 B/event — and the second correction was the error bar, because a bare `273` implies a precision a page-quantized file cannot carry. Both numbers came from the same code; only the measurement was wrong, which is the failure mode that makes benchmark numbers worth distrusting by default.

**Stopping the daemon because a peer hung up.** `ServeStdio` was called inline from `main`. It returns at stdin EOF, which under any service manager is immediate — systemd's `StandardInput=` defaults to `null` — so the daemon took its normal shutdown path and exited 0 in about 57 ms, and `Restart=always` turned the documented install into a five-second loop whose pollers never reached a first tick. The mistake was treating the analyst tier's query surface as the daemon's main loop. Both transports now run in a supervised goroutine and only SIGINT/SIGTERM cancels the context; losing the transport degrades tier 2 and says so, on a WARN and on `vigilo_mcp_transport_up`. `test/e2e/stdio_test.go` pins it, and it is there because the gap survived a full e2e suite that ran every daemon on `http`: a default that no automated path exercises is a default that is not tested. What is not fixed is the consequence — the shipped config still ships tier 2 dark; see `docs/THREAT_MODEL.md`, Pillar 6.

## Where this design's limits are, and what would lift them

**File events carry no process attribution, and inotify cannot provide it.** A file event says a watched path was written; it does not say by what. `fsnotify.Event` is `{Name string, Op Op}` — there is no PID field, because the kernel's `struct inotify_event` has none. Verified on the running stack: a write to a watched `.env` produces `{"action":"write","resource":"/app/.env","pid":0,"process":"","detail":""}`. For incident response this is materially weaker than it sounds — "a keystore was written" without "by which process" leaves the responder to reconstruct attribution from the process and network collectors by timestamp, which is correlation, not evidence.

Lifting it means changing the collection mechanism, not the code around it:
- **`auditd` (already implemented, opt-in).** `AuditdWatcher` parses `SYSCALL`+`PATH` record groups and populates PID, `comm`, `exe` and UID, and sees opens, execs, deletes and renames. Cost: Linux with auditd running, audit rules keyed `vigilo_*` installed out of band, and read access to `/var/log/audit/audit.log` (adm group or root) — a privilege the hardened unit otherwise avoids.
- **`fanotify`.** Gives both reads and the accessing PID without an external daemon, at the cost of `CAP_SYS_ADMIN` for the useful mark modes — which is exactly the capability `CapabilityBoundingSet=` exists to deny. That trade is real and has not been made.

**Polling is sampling, and sampling has blind spots.** The process and network collectors diff `/proc` on a ticker (default 5s). Three consequences, all reproduced live at `poll_interval: 1s`:
- A parent/child pair that both appear between two scans is not flagged, because `checkProcess` requires the parent to be present in a *previous* scan (`pw.seen[p.ppid]`). Verified: a `node`-named binary that spawns a shell immediately produced no event; the same binary sleeping 6s first produced a critical `node → sh` alert.
- Classification uses `comm` as sampled at tick time. A shell that immediately `exec`s something else — `sh -c "sleep 6"`, which `ash` turns into a direct exec — is `sleep` by the time the poller looks, and is not flagged. Adding a second command (`sh -c "sleep 6; true"`) keeps it a shell and it is flagged.
- Connections that open and close between polls are never in `/proc/net/tcp` when it is read.

Lifting this means an event-driven source: the kernel proc connector (netlink) for exec/exit, or eBPF for both process and socket events. Both are strictly more invasive than reading `/proc`, and eBPF re-introduces a privilege requirement. Neither is implemented.

**The shipped default serves tier 1 and leaves tier 2 unreachable.** `mcp_transport: stdio` is the default in `config.example.yaml`, and `deploy/install.sh` copies that file verbatim to `/etc/vigilo/config.yaml`. `ServeStdio` returns at stdin EOF, which under a service manager is immediate — systemd's `StandardInput=` defaults to `null`, "i.e. all read attempts by the process will result in immediate EOF" (systemd's own `systemd.exec` documentation), and `deploy/vigilo.service` does not override it. Collection and immediate alerting are unaffected, by construction: the transport is supervised and only SIGINT/SIGTERM ends the process. What is unaffected is not the same as what is working — on an untouched install the analyst tier can never connect, and the operator has to set `mcp_transport: http` with a token to get it. The daemon reports this (WARN, `vigilo_mcp_transport_up` 0, `mcp_transport_up:false` on `/healthz`), but `web_addr` has no default either, so on that same untouched config the two endpoints carrying the signal are not served and the journal line is the whole story. Nothing alerts on it. Carried in `THREAT_MODEL.md`, Pillar 6.

**One host, one daemon, no self-protection.** There is no heartbeat, dead-man's switch or tamper-evidence on the event store. A daemon that is killed, or never started, is indistinguishable from a quiet host to anyone not already watching for its absence.

## What this design explicitly does not solve

- It does not prevent anything. Every control described here is observation; none of it stands between an attacker and a file.
- It does not defend against a compromised kernel, a rootkit, or an attacker with root on the monitored host — who can stop the daemon, edit its config, or delete the store before anything is pushed.
- It does not give cryptographic integrity for the event trail. The store is a local SQLite file protected by filesystem permissions, with no signing and no hash chaining; a writer with access can alter or delete history without leaving a gap to find.
- It does not make the LLM tier a security boundary. The analyst reads attacker-influenceable text and produces advisory prose; see `docs/THREAT_MODEL.md`.
- It has no event-correlation layer, and the collector is the wrong place for one. `file.go` classifies and emits one `fsnotify` event at a time with no window, so a `rename` cannot be distinguished from the `rename` + `Create` pair an in-directory move produces — the daemon cannot tell "a key left the watched tree" from "a key was saved atomically". Tier 1 has the sequence and no correlation logic; tier 2 has correlation and is not on the alert path. See #30 and #31.
- It has never been run against real adversarial traffic. Every number here comes from a controlled harness that triggers its own events, at the commits pinned above; `eval/.gitignore` excludes `results/`, so no run artefact is in the repository.
