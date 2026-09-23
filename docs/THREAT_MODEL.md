# Threat model

What vigilo defends, per pillar, framed as Prevent / Contain / Detect — and, just as deliberately, what it does not. Every claim below is grounded in this repository's code, its tests, or a live run against the daemon; where a guarantee is conditional the condition is stated in the same sentence as the guarantee.

Read the top-level framing first: **vigilo prevents nothing on the monitored host.** It is a detection and alerting daemon running as an unprivileged user with no capabilities. "Prevent" in the pillars below means preventing misuse *of vigilo itself* — of its listeners, its event store and its alert path. Nothing here stands between an attacker and a private key.

## Assets

- **The keys and secrets on the monitored host** — what the attacker wants. Vigilo never holds them, only observes paths that contain them.
- **The event store** (`/var/lib/vigilo/events.db`) — a timestamped map of where the sensitive files on this host are, what processes run, and what the host talks to. Reading it is reconnaissance.
- **The alert path** — Slack/Telegram/SMTP/webhook credentials, and the property that an alert actually arrives.
- **The MCP and dashboard listeners** — read interfaces onto the event store.
- **Operator attention** — a finite asset. A flood of low-value alerts is an attack on it.

## Actors and trust boundaries

| Actor | Trust level |
|---|---|
| The operator | Trusted, but can bind a listener to the wrong interface, omit a token, or write a suppression rule that swallows a real signal |
| An unprivileged process on the monitored host | Untrusted; can generate arbitrary filenames, process names and argv, all of which become event content |
| Root on the monitored host | Out of scope entirely — can stop the daemon, edit config, or delete the store. Every guarantee below assumes the attacker has not reached root |
| The event store file | Trusted by every reader; integrity rests on filesystem permissions alone |
| The MCP client / analyst agent | Semi-trusted; holds a bearer token that grants full read of the event store |
| Claude (the analyst model) | Untrusted as a decision-maker; receives attacker-influenceable text and produces advisory output |
| Alert destinations (Slack, Telegram, SMTP, webhook) | Third parties; receive event content including attacker-chosen paths |

---

## Pillar 1 — Collection (`internal/collector`)

**Detect:** creates, writes, removes and renames on configured `watch_paths` — `file.go` handles all four `fsnotify` ops, with `TestFileWatcherDetectsRemove` and `TestFileWatcherDetectsMoveOut` covering the two added in #27 — severity assigned by substring match on the path (`keystore`, `wallet.json`, `.pem`, `id_rsa`, `mnemonic` → critical; `.env`, `secret`, `credentials`, `seed` → high). Suspicious process spawns, as parent→child pairs from a fixed map (`node`/`python`/`python3`/`java`/`nginx` spawning a shell, `curl`, `wget`, `nc`). New established outbound TCP connections on ports that are neither known-safe nor known-bad, and any connection matching a configured IOC range. Dependency-manifest tampering when the supply-chain guard is enabled with explicit roots.

**Contain:** collectors emit into a bounded channel (512) and every send is `select`-ed against a stop channel, so a collector blocked on a send observes shutdown and returns instead of hanging. This narrows the closed-channel panic window rather than closing it: `stopCollectors()` does not wait for collector goroutines to exit before `close(events)`, and a `select` with both a ready send and a closed stop channel may still take the send. IOC matching runs on the *baseline* scan as well as subsequent ones, so a C2 session that predates the daemon — the normal case on a host where vigilo is installed *because* something is wrong — is not absorbed into the baseline.

**Explicit non-goals:**

- **Reads are not detected by the default file collector, at all.** fsnotify's inotify backend subscribes to `IN_CREATE | IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF | IN_DELETE | IN_DELETE_SELF` and never to `IN_ACCESS`. Verified live against the running stack: `cat` on a watched keystore file produced no event; a write to the same path alerted. `auditd` (opt-in, `auditd_log_path`) is the only shipped path that observes reads.
- **A rename event says a watched path stopped being that path; it does not say the file left the tree, and nothing correlates the two cases.** fsnotify sends `Rename` with the *old* path as `Event.Name`; an in-directory move additionally sends `Create` with the new name, while "renaming a file to outside a monitored directory will show up as only a Rename" (fsnotify v1.7.0, `backend_inotify.go`). So a move out of the watched tree and a move within it differ only by whether a matching `Create` follows — and `file.go` classifies and emits each event on its own, with no window and no pairing. Only an *uncorrelated* rename means the file is gone, and the collector cannot tell you which kind it just sent. The cost runs in the benign direction too: an atomic save (write temp, rename into place — how geth and most wallet software persists keys) emits a rename on a temp path that the substring severity match reads as critical, on every routine save (#30). Reads remain the one half of exfiltration the default collector cannot see at all.
- **File events carry no process attribution.** `fsnotify.Event` is `{Name, Op}`; the kernel's `struct inotify_event` has no PID, so there is nothing to propagate. A live file alert is literally `{"action":"write","resource":"/app/.env","pid":0,"process":"","detail":""}`. A responder learns *that* a watched path changed, never *by what*. Only the `auditd` collector populates PID/`comm`/`exe`/UID.
- **Polling is sampling.** Process and network collection diff `/proc` on a ticker (default 5s). Three reproduced blind spots, all at the *faster* 1s eval interval:
  - A parent and its child that both first appear in the same scan are not flagged — `checkProcess` returns early unless the parent was recorded in a previous scan. Verified: a `node`-named binary spawning a shell immediately produced nothing; the same binary sleeping 6s first produced a critical `node → sh`.
  - Classification uses `comm` as sampled at tick time, so a shell that immediately `exec`s something else evades. Verified: `sh -c "sleep 6"` (which `ash` turns into a direct exec) produced nothing; `sh -c "sleep 6; true"` produced a critical alert.
  - A connection that opens and closes between two polls is never in `/proc/net/tcp` when it is read.
- **Process matching is on `comm`, which the attacker controls.** The parent map is keyed on five literal names. Renaming or copying a binary defeats it; so does any parent not in the map.
- **Severity is a substring match on the path, which the attacker also controls.** Writing to a path with no matching substring yields `info` and never alerts; the same file renamed to contain `keystore` yields `critical`.
- **Directories created after startup more than one level deep are not watched.** The watcher adds a new directory when it sees its `Create` event; a nested tree created in one operation (`mkdir -p a/b/c`) races that. Verified live: after `mkdir -p new/deep/tree`, a `wallet.json` written inside produced **no event**, while a single-level `mkdir flat` followed by the same write *was* detected, and paths that existed before startup are covered by the initial recursive walk.
- **Suppression rules are unanchored, case-insensitive substring matches** against the resource *or* process name, scoped optionally by source. An attacker who can choose a path containing a rule's literal substring is dropped before the buffer. Verified live with the shipped example rule `match: /var/backups/`, `source: file_access`: a write to `<watched>/var/backups/wallet.json` produced no event at all, while the same write elsewhere was critical. Source scoping does hold — a file named `datadog-agent-wallet.json` was *not* suppressed by the `source: process` rule of the same name.
- **No UDP, no DNS.** Only `/proc/net/tcp` and `/proc/net/tcp6` are parsed. DNS-tunnelled exfiltration and UDP C2 are invisible.
- **Exfiltration over 443 is not flagged by the port heuristics**, by design: 80, 443, 53, 22 and common chain RPC ports are on the known-safe list. The IOC store is the only mechanism that catches C2 on a safe port, it is operator-supplied, and `include_known_c2` ships **off** (enabling it on a host that uses vigilo's own Telegram alerter makes vigilo alert on itself).
- Nothing here detects in-memory-only activity, kernel-level compromise, or anything on a host where the daemon is not running.

---

## Pillar 2 — Event store (`internal/buffer`)

**Prevent:** SQL injection on the query path — every filter is a bound parameter. `LIMIT` is clamped to 1000 regardless of caller input, so no query is unbounded.

**Contain:** the store is a local file under a dedicated user, never exposed over a network directly. Retention is bounded (`buffer_retention_hours`, default 24) with an hourly prune, so the window of host reconnaissance available from a stolen database file is bounded too.

**Detect:** nothing. The store records; it does not police itself.

**Explicit non-goals:**

- **No integrity protection whatsoever.** No signing, no hash chaining, no append-only mode. Anyone who can write the file can alter or delete history, and there is no gap left behind to find. This is strictly weaker than the "tamper-evident" property the word "buffer" might suggest.
- **Confidentiality rests entirely on filesystem permissions.** The database is not encrypted at rest. `SECURITY.md` describes it as mode 0600; the daemon does not itself enforce a umask or verify the mode at startup, so this is a property of the install (`deploy/install.sh` chowns the directory), not an invariant the code maintains.
- **The hourly prune ticker fires first at T+1h**, so a daemon restarted frequently may never prune. Retention is a ceiling, not a schedule.
- **`Store.IsDuplicate` and the `signal_dedup` table are dead code** — grep across Go, TypeScript and Python finds no caller. They are noted here because the function contains a defect that will become live the moment it is wired up: it formats timestamps with `time.RFC3339`, which has no sub-second component, then string-compares `lastSeen >= cutoff`. Reproduced with a throwaway test, 5/5 runs: with `cooldown = 0` (which reads as "dedup disabled"), two calls for the same hash **400 ms apart in the same wall-clock second are suppressed**, while two calls straddling a second boundary are not. Any cooldown below one second behaves the same way — `cooldown = 10ms` with a 300 ms gap also suppressed. So the behaviour is not "cooldown 0 means one second"; it depends on where in the second the events land, which is exactly how a defect like this survives casual testing.

---

## Pillar 3 — Immediate alerting (`internal/alerter`)

**Detect:** any event at or above `alerter.min_severity` (default `high`) is pushed to every configured channel within roughly a second of the collector observing it. Measured in the isolated eval stack at commit `14015e2`, n=10 per chain: `keystore_write` 87.8 ms median / 282.5 ms p95; `env_write` 53.9 ms / 60.4 ms; `suspicious_outbound` 623.1 ms / 1013.0 ms, the last at `poll_interval: 1s` and meaningless without that qualifier. That pass predates #27, so it measured a collector that could not emit a remove or a rename; the two new actions have no latency figure. `eval/.gitignore` excludes `results/`, so no run artefact is checked in — the SHA is the only provenance these numbers carry.

**Contain:** each channel gets one immediate retry on failure; a send failing on every channel is counted (`vigilo_alerts_dropped`) and logged at ERROR with the event id, source and severity. The dispatcher never blocks the drain goroutine — alerts fire in their own goroutine.

**Explicit non-goals:**

- **Repeated access to the same resource alerts once per cooldown window, and the shipped default window is an hour.** `eventFingerprint` hashes `source + resource`; the action is deliberately excluded, so every action on one path is one signal. Verified live with `signal_cooldown: 1h` (the value in `config.example.yaml`): three writes to the same `wallet.json` two seconds apart produced **three stored events but one delivered alert**. This matters because rapid repeated access to one key file is the signature of an actual extraction rather than a routine write, and the push tier collapses exactly that shape. The events remain visible to the dashboard and to the analyst tier; only the push is suppressed.
- **Excluding the action from the fingerprint now swallows the signal #27 was added for.** Since remove and rename became real events, `create`/`write`/`remove`/`rename` on one path share a fingerprint — so a routine write suppresses the push for a subsequent rename of that same path for the rest of the hour, and an uncorrelated rename is exactly the move-out of the watched tree that #27 exists to catch. The guarantee and its condition in one sentence: a rename is pushed within roughly a second *provided nothing else touched that path inside the preceding cooldown window*. The event is still stored and still visible to the analyst tier and the dashboard; only the push is lost. Tracked as #31.
- **The dedup entry is written before any channel send is attempted** (`d.dedupCache[fp]` is set under the lock, before the send loop), so an alert that fails on every channel still occupies its fingerprint for the whole cooldown. A channel outage at the wrong moment silently costs an hour of push coverage for that resource. Also #31.
- **The dedup cache is in-process.** A restart clears it — which cuts both ways: repeat alerts return, and an attacker able to restart the daemon resets suppression state.
- **No delivery guarantee and no queue.** After one retry the alert is dropped. There is no persistent outbox, no dead-lettering, and no back-off beyond the single 500 ms retry.
- **Alert content is attacker-influenceable text interpolated into markup without escaping.** `resource`, `process` and `detail` originate from filenames and argv. `slack.go` places them inside a `mrkdwn` block; `telegram.go` places them inside `<code>` tags and sends with `parse_mode: HTML`. Neither escapes the value first. A filename containing a backtick, `<` or `&` therefore reaches a markup parser as markup. What that yields — rendered link injection into a security channel, or a message the receiving API rejects outright, which would cost the alert after its single retry while its dedup fingerprint is already burned — depends on Slack's and Telegram's parsers, which have **not** been tested here. The unescaped interpolation is verified from the code; the downstream effect is not.
- **`alerts_sent` counts a dispatch where at least one channel succeeded**, not per-channel delivery. A permanently broken Telegram config alongside a working Slack one shows zero drops.
- **Nothing alerts on the absence of alerts.** There is no heartbeat and no dead-man's switch; a silent daemon and a silent host look identical.

---

## Pillar 4 — Query surfaces (`internal/mcp`, `internal/web`)

**Prevent:**

- MCP over HTTP requires `Authorization: Bearer <token>` matched in constant time, and the daemon **refuses to start** on `mcp_transport: http` with no token unless `mcp_allow_unauthenticated: true` is set explicitly, which logs a WARN (`test/e2e/mcp_auth_test.go` asserts both the refusal and the opt-out end to end, against a running daemon).
- Multiple `Authorization` headers are rejected rather than resolved to the first, and there is deliberately no `?token=` form on MCP, because a token in a URL reaches browser history, proxy logs and `Referer`.
- Any request carrying an `Origin` header is refused with 403, because the SSE library sets `Access-Control-Allow-Origin: *` unconditionally and a browser is never a legitimate MCP client.
- The web dashboard's data routes (`/`, `/api/events`, `/events/stream`) require a token when `web_token` / `VIGILO_WEB_TOKEN` is set, compared in constant time.
- The web API validates `since`, `limit` (1–1000), `severity` and `source` against allowlists and returns 400 otherwise.

**Contain:** the web server rate-limits 60 req/min per IP with a burst of 20, caps SSE subscribers at 100, and drops events for a subscriber whose buffer is full rather than blocking the broadcaster. MCP tools are read-only: there is no tool that writes, deletes, reconfigures or suppresses.

**Detect:** every web request is access-logged with method, path, status, latency and remote IP.

**Explicit non-goals:**

- **`/healthz` and `/metrics` are not behind authentication, even when `web_token` is set.** Verified live with a token configured: both return 200 with no credential while `/api/events` correctly returns 401. Two consequences worth naming:
  - `/metrics` serves Go's default `expvar` publications, which include `cmdline` — the daemon's full argv, i.e. its config and database paths — and `memstats`.
  - `/healthz` returns `events_buffered`, a rolling 24-hour event count. Anyone who can reach the port has an unauthenticated oracle for "did that action produce an event?", which is directly useful for probing the detection boundary before acting.
  - `/healthz` also returns `mcp_transport_up`, and `/metrics` publishes it as `vigilo_mcp_transport_up`. It is there so the loss of the analyst tier is not a single log line that scrolls away, but it is a second unauthenticated oracle: it tells an uncredentialed caller whether tier 2 can currently reach this daemon, i.e. whether anything is correlating events right now.
- **The dashboard accepts `?token=` in the query string.** This is a deliberate trade for browser navigation, which cannot set headers, and is not offered on MCP. Vigilo's own access log records `r.URL.Path` only, not the query — but browser history, any intermediate proxy and `Referer` still see it.
- **There is no TLS anywhere.** Both listeners are plain HTTP; the bearer token crosses the wire in cleartext unless an operator fronts it with a reverse proxy or confines it to a WireGuard/Tailscale interface, which the documentation recommends but nothing enforces.
- **The token is a single static shared secret with no expiry, no rotation and no revocation.** In the documented multi-host topology every daemon is given the *same* token and the agent sends it to all of them, so one compromised daemon's config yields read access to the event store of every monitored host. Rotation is "edit the env file and restart the fleet". There is no per-client identity and no audit of *which* client read what.
- **MCP over stdio has no authentication at all** — its boundary is process isolation, nothing more.
- **`Origin` rejection is not DNS-rebinding protection.** A rebound request is same-origin and carries no `Origin` header; the token is what stops that, which is why loopback binding is not a substitute for setting one.
- **Constant-time comparison hides the token's contents, not its length** — `ConstantTimeCompare` returns early on a length mismatch. The web server says so in its own comment.
- **The per-IP rate-limiter map is never evicted.** It grows one entry per distinct source IP for the process lifetime; harmless on loopback, a memory-growth vector on any wider binding.
- **A valid token grants everything.** There is no scoping, so a client authorised to read process events can read every keystore path on the host.

---

## Pillar 5 — The LLM analyst (`agent/`)

This is the pillar where the trust boundary is least intuitive, so state it plainly: **the analyst consumes attacker-influenceable text and is not a security decision-maker.** Framing follows the OWASP Top 10 for Agentic Applications, which is about what is structurally different once a model is in the loop.

**Contain (this is the important one):** the analyst's authority is extremely narrow, and deliberately so.

- Its entire tool surface is five read-only MCP queries — the five `agent/src/collectors/mcp.ts` wraps, of the six `internal/mcp/server.go` registers and the bearer token reaches. It has no write tool, no shell, no filesystem access, and no ability to change daemon config, suppression rules or alert routing. The boundary is the tool set the daemon exposes, not the subset the agent happens to call: a stolen agent token reaches all six.
- Its only externally visible effect is posting a Slack message. It cannot suppress a tier-1 alert, quarantine a host, or take any action on the monitored machine.
- It is a **fixed workflow, not an autonomous loop**: cron-triggered, one Claude call plus at most two corrective re-asks (a missing `<dup_check>` block, then unparseable JSON), a structured parse, a post. The model directs no control flow. This is the ASI06 (excessive agency) mitigation, and it is structural rather than policy-based.
- Output parsing scans backwards for the last complete JSON array rather than greedily matching, so trailing prose cannot produce a malformed superset. The direction of that failure is deliberate — an unparseable response yields zero signals, not garbage, which is safe for the channel and silent for the incident. It is also the cheapest way to silence this tier; see the non-goals.

**Detect:** multi-step and cross-host patterns that single-event rules cannot express — the reason this tier exists.

**Explicit non-goals:**

- **Prompt injection through watched content is unmitigated.** Events are serialised verbatim into the user message, and `resource`, `cmd_line`, `detail` and `process` derive from filenames and process arguments. Anyone who can create a file or run a process with a chosen name can place text of their choosing in the model's context (ASI01 goal hijacking / ASI04 context poisoning). There is no delimiting, escaping, provenance marking or instruction-boundary defence in `agent/src/agents/analyst.ts`. The realistic objectives are suppression ("no threats detected") and content injection into the Slack post; both stay within the tier-2 channel. Note the containment that survives regardless: an injection cannot reach a tool the agent does not have, and **cannot suppress a tier-1 alert**, which has already fired from the daemon without consulting any model.
- **Silencing this tier does not require persuading the model. A filename does it.** `findLastJsonArray` counts raw `[` and `]` characters with no string-awareness, so a single unbalanced bracket anywhere in the model's response — including one echoed back from an attacker-chosen path — breaks the scan. Reproduced against the shipped function: a response whose description contains `/app/wallet].json` returns `null`, and one containing `/app/wallet[.json` returns a fragment starting mid-string that `JSON.parse` rejects. Either way `parseSignals` returns `null`, the one corrective re-ask runs, and `analyzeEvents` then `return []`. `index.ts` treats an empty signal list as a clean scan and posts `:white_check_mark: Vigilo scan — N events, no threats detected` with N non-zero. This is a deterministic parser defect, distinct from and cheaper than the model-compliance attacks above: no injection, no model cooperation. Tracked as #32. What still holds: tier-1 pushes for those same events already fired from the daemon, so this silences correlation, not detection.
- **The analyst's window is small and displaceable, which makes flooding a practical evasion.** Each scan fetches `medium`-and-above events from the last 6 minutes with `limit: 200`, ordered newest-first, then compacts to at most 150: critical/high first, medium/info sampled 1-in-3, and the concatenation truncated to 150 — so beyond 150 critical/high events in one window, even high-severity events are cut. An attacker who generates more than 200 qualifying events inside the window pushes the real one out of the query result before the model ever sees it. `info` events never reach this tier at all. Compaction has a second consequence: the model is handed indices into the compacted, severity-reordered list, and `index.ts` resolves `evidenceIndices` against the *uncompacted* `allEvents`. Below 150 events the two lists are the same object and the indices are right; above it they are not, so a posted signal cites evidence rows that are not the ones the model reasoned about — misattributed evidence in exactly the flood conditions where an operator most needs it, and `.filter(Boolean)` drops any index past the end without saying so. Tracked as #33.
- **Signal dedup is keyed on model-generated text.** The hash is `category + normalised title + server`, with a 1-hour default TTL, so two genuinely distinct incidents that the model titles alike collapse to one alert — and a title steered by injection can collide with a previously-alerted signal on purpose.
- **A clean scan posts an affirmative "no threats detected" message.** That statement is only as good as the window it saw and the parse that produced it, and both have all the limits above — an analysis that was never parsed is reported identically to one that found nothing.
- **No evaluation of the analyst tier exists.** The measured evaluation in `eval/` covers the immediate tier only; the analyst was out of scope for that pass. There are no recall figures, no injection-resistance tests, and no adversarial corpus for this pillar. Nothing here has been measured.
- **`ANTHROPIC_API_KEY` in the agent environment is a third-party dependency and a cost surface.** Event content — file paths, command lines, host labels — is sent to the Anthropic API. That is a data-egress decision an operator has to make knowingly.

---

## Pillar 6 — Deployment and secrets

**Prevent:** the shipped systemd unit runs as a dedicated non-login user with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, an empty `CapabilityBoundingSet` and an empty `AmbientCapabilities`, with `ReadWritePaths` limited to `/var/lib/vigilo`.

**Contain:** secrets are read from the environment in preference to config (`VIGILO_MCP_TOKEN`, `VIGILO_WEB_TOKEN`, `VIGILO_SLACK_WEBHOOK_URL`, `VIGILO_TELEGRAM_BOT_TOKEN`, `VIGILO_TELEGRAM_CHAT_ID`, `VIGILO_SMTP_PASSWORD`), sourced from `EnvironmentFile=-/etc/vigilo/env` so they need never appear in a config file or a container image. Alert channels are outbound-only.

**Explicit non-goals:**

- **The documented install ships tier 1 working and tier 2 dark.** `ServeStdio` returns at EOF, and under a service manager stdin is `/dev/null` and reaches EOF immediately: systemd's `StandardInput=` defaults to `null`, "i.e. all read attempts by the process will result in immediate EOF", and `deploy/vigilo.service` does not override it. Since #25 the transport runs in a supervised goroutine and only SIGINT/SIGTERM cancels the daemon's context, so collection and immediate alerting continue — `test/e2e/stdio_test.go` asserts the daemon survives stdin EOF, and the fix is in the published `v0.2.0` (tagged at `94a1d37`, which has #25 as an ancestor). What is lost is the analyst tier: nothing can reach the MCP query surface for the life of the process. The daemon logs a WARN naming the cause, sets `vigilo_mcp_transport_up` to 0 and reports `mcp_transport_up:false` on `/healthz`. `deploy/install.sh` copies `config.example.yaml` — which sets `mcp_transport: stdio` — verbatim to `/etc/vigilo/config.yaml`, so an operator who follows the quick start and changes nothing gets tier 1 alerting and no tier 2, until they set `mcp_transport: http` with a token. The signal exists; nothing acts on it. `web_addr` has no default and ships commented out, so on that same untouched config `/healthz` and `/metrics` are not served at all and the WARN in the journal is the only trace. There is no alert, no non-zero exit and no `systemctl status` difference.
- **`mcp_addr` defaults to loopback, and `mcp_addr: ":7070"` binds every interface.** The daemon substitutes the loopback default only when the field is empty, specifically so a blank address cannot become `:80`; an explicitly wrong value is honoured.
- **The shipped `docker-compose.yml` is not a hardened deployment shape.** It mounts host `/proc` and `/home:ro` and sets `network_mode: host`, so the container observes — and can egress from — the real host. The evaluation stack deliberately does not reuse it, and says so in its own header: a triggered "suspicious outbound connection" would leave from the real machine's real IP. It also mounts `config.example.yaml` directly and so inherits the stdio default above, while its own comment claims "SSE/HTTP mode so the agent can connect" and it publishes port 7070 — the `agent` service it starts alongside cannot reach a transport that is not listening. Treat it as a demonstration, not a production topology.
- **Secrets are never rotated by anything here.** There is no generation helper beyond a documented `openssl rand -hex 32`, no expiry, no revocation list. `config.example.yaml` ships with realistic-looking placeholder Slack and Telegram credentials uncommented, which is a live invitation to commit a real one in the same position.
- **The event store's own file mode is not enforced by the daemon.** `deploy/install.sh` chowns the data directory; the code does not check or set a mode at startup.
- **The supply-chain guard is off by default and requires explicit roots**; enabled with no usable root, it logs ERROR and does not start rather than scanning nothing silently. Its coverage is Terraform and npm manifests only.

---

## Residual risks, consolidated

- **An attacker with root on the monitored host defeats everything here.** They can stop the daemon, rewrite its config, add a suppression rule, or delete the event store — none of which leaves any trace vigilo can report.
- **Killing the daemon is undetectable from inside vigilo.** No heartbeat, no dead-man's switch. "Vigilo is installed and enabled" is not equivalent to "vigilo is watching", and nothing in the system distinguishes the two. The narrower version of the same shape survives on the analyst tier: on the untouched shipped config, tier 2 is unreachable from first start, `mcp_transport_up` says so, and nothing reads it.
- **The event trail is not tamper-evident.** No signing, no hash chaining. Anyone with write access can alter history silently.
- **Two independent evasion paths against file detection have been reproduced live**: reads are invisible to the default collector, and directories created more than one level deep after startup are never watched (#28). A third — removes and renames dropped by the collector's own filter — was reproduced and is fixed on `main` (#27, closing #24), but `v0.2.0` was tagged at `94a1d37` and does not contain it, so an operator running the current release still has that path open. What replaces it is narrower and is a classification gap rather than an evasion: a rename event does not distinguish a move out of the watched tree from a move within it, because nothing correlates the rename with the `Create` that an in-tree move also emits.
- **Two independent evasion paths against process detection have been reproduced live**: a parent/child pair born inside one poll interval, and a shell that immediately `exec`s something else.
- **Alert suppression is a two-edged control.** Unanchored substring suppression rules can be satisfied by an attacker-chosen path (reproduced), and the default one-hour push cooldown on `source + resource` collapses the repeated-access pattern that most distinguishes extraction from routine work (reproduced). Because the fingerprint excludes the action, that same window now also suppresses the push for a rename following any other touch of the path — the exact signal #27 was added to surface (#31).
- **The analyst tier has a small, displaceable window, no injection defence, and a parser that a filename can break** (#32, #33), and no measured evaluation of any kind. Its containment is structural — read-only tools, Slack-post-only authority, no ability to touch tier 1 — not behavioural, and every one of those failures degrades tier 2 while tier 1 keeps firing.
- **A single static token, shared fleet-wide, guards a read interface onto every monitored host's secret-file layout.** No rotation, no revocation, no per-client identity, no TLS by default.
- **The false-positive figure is 0, measured over a 60-second bounded window of in-container dev activity, with no suppression tuning.** The harness itself refuses to report a vacuous zero and carries the qualifier in its output; repeating the number without the qualifier would be dishonest. It is not a production signer's noise profile, and no long-window measurement exists. It also predates #27: it was measured at `14015e2`, against a collector that could not emit a remove or a rename on the default watch paths, so it is not a statement about current `main` — #30 argues the opposite direction, that routine atomic saves on those paths now produce critical renames.
- **Every number in this repository comes from a controlled harness that triggers its own events, and none of them is checked in.** `eval/.gitignore` excludes `results/`, so each figure's provenance is the commit it is pinned to here and nothing else. Vigilo is published (`v0.2.0`) but has never been deployed to a production validator and never run against real adversarial traffic. Throughput under a real event flood has not been measured at all.

## Reporting

Security issues go to `security@voltagebots.com`, privately, per `SECURITY.md` — not a public issue.
