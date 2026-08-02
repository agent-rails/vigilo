# Supply-Chain Guard

Tier-0 (rules, no LLM) collector that scans dependency manifests, lockfiles, and
package-manager CLI config for supply-chain tampering — the delivery vector behind
the DPRK "Contagious Interview" campaign, which ships the same infostealer via
Terraform providers, npm lifecycle scripts, pip, cargo, and more.

It is a **software factory**: shared machinery + pluggable per-ecosystem analyzers.
Adding a new ecosystem is a mechanical act — one file, one registration line, one
config block — with no changes to the guard.

## Architecture

```
SupplyChainGuard (internal/collector/supplychain.go)
  owns: walk roots, schedule, read-once, dedup, suppress, emit
  routes each matched file -> Ecosystem analyzers
        |
        Ecosystem interface:
          Name() string
          Matches(filename string) bool
          Inspect(path string, content []byte) []Event
        (optional) ExtraPathProvider: ExtraPaths() []string   # out-of-root files
        |
        +- TerraformEcosystem (terraform.go)  # provider typosquat / mirror / hash-pin
        +- NpmEcosystem       (npm.go)        # install scripts / registry substitution
        +- <your ecosystem>   (…)
```

Findings are emitted as `collector.Event{Source: SourceSupplyChain, …}` and flow
through the normal pipeline (SQLite buffer → immediate alerter on high/critical →
MCP for the analyst).

## Add an ecosystem

1. Create `internal/collector/<eco>.go` implementing `Ecosystem`:

   ```go
   type PipEcosystem struct{ allowed []string }

   func NewPipEcosystem(allowed []string) *PipEcosystem { /* defaults */ }

   func (p *PipEcosystem) Name() string { return "pip" }

   func (p *PipEcosystem) Matches(f string) bool {
       return f == "requirements.txt" || f == "poetry.lock" || f == "Pipfile.lock"
   }

   func (p *PipEcosystem) Inspect(path string, content []byte) []Event {
       // parse; return Events with Source: SourceSupplyChain, an Action,
       // a Severity, and a Detail. Must be pure + deterministic.
   }
   ```

2. Add a conformance test — inherit the whole invariant suite for free:

   ```go
   func TestPipConformance(t *testing.T) {
       runEcosystemConformance(t, ecosystemConformance{
           ecosystem: NewPipEcosystem(nil),
           match:     []string{"requirements.txt", "poetry.lock"},
           nonMatch:  []string{"package.json", ".terraform.lock.hcl"},
           cases: []conformanceCase{
               {name: "clean", file: "requirements.txt", content: "...", want: nil},
               {name: "rogue index", file: "requirements.txt", content: "...",
                   want: []expectedFinding{{"pip_untrusted_index", SeverityHigh}}},
           },
       })
   }
   ```

3. Add a config sub-block in `internal/config/config.go`
   (`SupplyChainGuardConfig.Pip *PipEcosystemConfig`) and register it in
   `cmd/vigilo/main.go` `buildEcosystems`:

   ```go
   if p := cfg.Pip; p != nil && p.Enabled {
       out = append(out, collector.NewPipEcosystem(p.AllowedIndexes))
   }
   ```

That's the entire diff. The guard, walker, dedup, and event pipeline are untouched.

## Conformance contract

Every ecosystem must satisfy (enforced by `runEcosystemConformance`):

- `Name()` is non-empty.
- `Matches` accepts its own files and rejects other ecosystems' files (exclusivity).
- `Inspect` is **deterministic** (same input → same findings, order aside) and
  **pure** (never mutates its `content` argument).
- Every finding has `Source == SourceSupplyChain`, a non-empty `Action`, and a
  valid `Severity`.

## Config

```yaml
supply_chain_guard:
  enabled: true
  roots: ["~/code"]          # REQUIRED when enabled — no default.
                             # `~` and $VAR are both expanded.
                             # Roots that don't exist are dropped with an
                             # ERROR; if none survive, the guard won't start.
  scan_interval: 5m
  terraform:
    enabled: true
    allowed_provider_prefixes:
      - registry.terraform.io/hashicorp/
      - registry.terraform.io/blockopsnetwork/
    pinned_hashes: {}        # optional "source@version" -> [h1:…]
  npm:
    enabled: true
    allowed_registries:
      - registry.npmjs.org
```

## IOC matching (network)

Port heuristics structurally miss C2/exfil over :443 (a "safe" port) — which is
exactly what the Contagious Interview infostealer family uses (Telegram Bot-API
C2, e.g. 149.154.166.110:443). The IOC store closes that gap: the network collector
matches every new outbound connection's remote IP against known-bad ranges
**before** the port logic, so a known-bad IP is flagged regardless of port.

The store is the seam the security wiki feeds — confirmed-bad indicators become
detections with no code change.

```yaml
ioc:
  include_known_c2: false   # opt into built-in ranges (Telegram etc.).
                            # Leave off on any host running vigilo's own
                            # Telegram alerter, or it will self-alert.
  ip_ranges:                # operator/wiki-supplied indicators
    - cidr: 149.154.160.0/20
      label: "Telegram C2 (Contagious Interview)"
      severity: critical
```

Built-in `KnownC2IPRanges` (opt-in via `include_known_c2`) currently covers the
published Telegram Bot-API ranges used by the campaign. Extensible to file-path
and process-name indicators via the same `IOCStore`.

## Current detections

| Ecosystem | Finding (action) | Severity |
|---|---|---|
| terraform | `provider_typosquat` (near-miss of trusted namespace) | critical |
| terraform | `provider_untrusted_source` (non-allowlisted registry/namespace) | high |
| terraform | `provider_hash_mismatch` (lockfile hashes miss pinned set) | critical |
| terraform | `provider_mirror_config` (`dev_overrides` in `.terraformrc` — bypasses registry *and* lockfile checksums) | critical |
| terraform | `provider_mirror_config` (`network_mirror`/`filesystem_mirror` in `.terraformrc`) | high |
| terraform | `provider_lockfile_unparseable` (non-empty lockfile yielding no provider blocks — malformed or evasion) | high |
| npm | `npm_install_script` (payload-fetching lifecycle hook) | critical |
| npm | `npm_nonregistry_dependency` (any non-registry spec: URL, `git+*`, `file:`, `github:`/`owner/repo` shorthand) | high |
| npm | `npm_untrusted_registry` (lockfile `resolved` off-allowlist) | high |
| npm | `npm_registry_override` (`.npmrc` registry to non-allowlisted host) | high |

## Coverage boundaries

What the guard does **not** see, stated explicitly so the coverage claims above
aren't read as broader than they are:

- **Detection is post-fetch for the lockfile paths.** `.terraform.lock.hcl` is
  written by `terraform init` — the same command that already executed the
  provider. A finding there means the host has already run it, not that it is
  about to. The pre-execution signals are `.terraformrc`
  (`dev_overrides`/mirrors) and the npm manifest checks.
- **`node_modules` is scanned one level deep only.** Installed direct
  dependencies (`node_modules/<pkg>/package.json` and
  `node_modules/@scope/<pkg>/package.json`) are inspected, since that is where
  a BeaverTail-style lifecycle payload actually lives. Transitive dependencies
  nested deeper are not walked — that is a deliberate cost trade-off, not an
  oversight.
- **Manifests over 5 MiB are skipped**, not truncated. A partial parse would
  produce findings that don't match what the package manager will do.
- **`TF_CLI_CONFIG_FILE` is read from vigilo's own environment**, not from the
  developer's shell. A per-shell override pointing at a hostile CLI config is
  invisible to the daemon; only the on-disk paths inside `roots` are covered.
- **Findings dedupe for 24h.** A re-planted identical payload re-alerts after
  that window, not before.
