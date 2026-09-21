package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// SuppressRule suppresses events whose resource or process contains Match.
// Source is optional — if empty the rule applies to all sources.
type SuppressRule struct {
	Match  string `yaml:"match"`  // substring to match against resource or process name
	Source string `yaml:"source"` // optional: file_access|process|network
	Reason string `yaml:"reason"` // human-readable explanation logged on suppression
}

type Config struct {
	// Paths to watch for sensitive file access
	WatchPaths []string `yaml:"watch_paths"`

	// Paths to exclude from watching (test fixtures, etc.)
	ExcludePaths []string `yaml:"exclude_paths"`

	// How often to poll /proc and network state
	PollInterval time.Duration `yaml:"poll_interval"`

	// SQLite buffer: keep last N hours of events
	BufferRetentionHours int `yaml:"buffer_retention_hours"`

	// MCP server transport: "stdio" or "http"
	MCPTransport string `yaml:"mcp_transport"`
	MCPAddr      string `yaml:"mcp_addr"` // only for http mode, e.g. "127.0.0.1:7070"

	// MCPToken is the Bearer token required for MCP HTTP transport access.
	// Set via VIGILO_MCP_TOKEN env var or mcp_token config field.
	// Empty = no auth (not recommended; the MCP tools expose the paths and
	// process lineage of everything vigilo watches).
	MCPToken string `yaml:"mcp_token"`

	// Alert webhook (optional — agent can also pull via MCP)
	AlertWebhookURL string `yaml:"alert_webhook_url"`

	// Anthropic key for local standalone mode
	AnthropicAPIKey string `yaml:"anthropic_api_key"`

	// Signal dedup cooldown — same signal won't re-alert within this window
	SignalCooldown time.Duration `yaml:"signal_cooldown"`

	// Suppress rules — events matching any rule are dropped before buffering
	SuppressRules []SuppressRule `yaml:"suppress_rules"`

	// AuditdLogPath enables the auditd collector when non-empty.
	// Typically /var/log/audit/audit.log — requires read access (adm group or root).
	// Only events matching audit rules with a "vigilo_" key prefix are processed.
	AuditdLogPath string `yaml:"auditd_log_path"`

	// WebAddr enables the web dashboard when non-empty (e.g. "127.0.0.1:7080").
	WebAddr string `yaml:"web_addr"`

	// WebToken is the Bearer token required for web dashboard access.
	// Set via VIGILO_WEB_TOKEN env var or web_token config field.
	// Empty = no auth (not recommended for production).
	WebToken string `yaml:"web_token"`

	// Immediate alerter — fires on high/critical events without waiting for LLM analysis
	Alerter AlerterConfig `yaml:"alerter"`

	// SupplyChainGuard scans dependency manifests / lockfiles / CLI config for
	// supply-chain tampering across pluggable ecosystems (Terraform today;
	// npm/pip/cargo as they're added).
	SupplyChainGuard SupplyChainGuardConfig `yaml:"supply_chain_guard"`

	// IOC configures indicator-of-compromise matching (known-bad IP ranges the
	// network collector flags regardless of port).
	IOC IOCConfig `yaml:"ioc"`
}

// IOCConfig holds indicator-of-compromise indicators fed to collectors.
// This is the seam the security wiki populates: confirmed-bad indicators become
// detections without code changes.
type IOCConfig struct {
	// IncludeKnownC2 opts into the built-in KnownC2IPRanges (Telegram etc.).
	// Off by default — enable only on hosts where such egress is anomalous
	// (a host running vigilo's own Telegram alerter would self-alert).
	IncludeKnownC2 bool `yaml:"include_known_c2"`

	// IPRanges are operator/wiki-supplied bad-IP indicators.
	IPRanges []IOCIPRangeConfig `yaml:"ip_ranges"`
}

// IOCIPRangeConfig is one bad-IP indicator.
type IOCIPRangeConfig struct {
	CIDR     string `yaml:"cidr"`
	Label    string `yaml:"label"`
	Severity string `yaml:"severity"` // info|medium|high|critical (default high)
}

// SupplyChainGuardConfig configures the generic supply-chain guard collector.
// Each ecosystem has its own sub-block; an ecosystem with Enabled=false (or
// absent) is not registered.
type SupplyChainGuardConfig struct {
	Enabled bool `yaml:"enabled"`

	// Roots to scan for manifests/lockfiles. Both `~` and $VAR are expanded.
	// REQUIRED when Enabled — there is no default: the service account is
	// created with --no-create-home, so a defaulted $HOME would silently
	// resolve to nothing and every scan would inspect zero files.
	Roots []string `yaml:"roots"`

	// How often to rescan. Defaults to 5m when zero.
	ScanInterval time.Duration `yaml:"scan_interval"`

	// Per-ecosystem configuration.
	Terraform *TerraformEcosystemConfig `yaml:"terraform"`
	Npm       *NpmEcosystemConfig       `yaml:"npm"`
}

// NpmEcosystemConfig configures the npm ecosystem analyzer.
type NpmEcosystemConfig struct {
	Enabled bool `yaml:"enabled"`

	// Allowlisted registry hosts. Empty = registry.npmjs.org only.
	AllowedRegistries []string `yaml:"allowed_registries"`
}

// TerraformEcosystemConfig configures the Terraform ecosystem analyzer.
type TerraformEcosystemConfig struct {
	Enabled bool `yaml:"enabled"`

	// Allowlisted provider source prefixes. Empty = official HashiCorp only.
	// Add your org namespaces, e.g. "registry.terraform.io/blockopsnetwork/".
	AllowedProviderPrefixes []string `yaml:"allowed_provider_prefixes"`

	// Optional pinned known-good hashes, keyed "source@version" -> list of
	// acceptable h1:/zh: hashes. A lockfile whose hashes miss all of these
	// (mirror swap) is flagged critical.
	PinnedHashes map[string][]string `yaml:"pinned_hashes"`
}

// AlerterConfig mirrors alerter.Config to avoid import cycles.
type AlerterConfig struct {
	MinSeverity string          `yaml:"min_severity"`
	Slack       *SlackConfig    `yaml:"slack"`
	Telegram    *TelegramConfig `yaml:"telegram"`
	Email       *EmailConfig    `yaml:"email"`
	Webhooks    []WebhookConfig `yaml:"webhooks"`
	Syslog      *SyslogConfig   `yaml:"syslog"`
}

type SyslogConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type EmailConfig struct {
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type WebhookConfig struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
}

var Defaults = Config{
	WatchPaths: []string{
		"$HOME/.ethereum",
		"$HOME/.bitcoin",
		"/etc/vigilo/keys",
		"/run/secrets",
	},
	PollInterval:         5 * time.Second,
	BufferRetentionHours: 24,
	MCPTransport:         "stdio",
	MCPAddr:              "127.0.0.1:7070",
	SignalCooldown:       time.Hour,
}

// Load reads the config file at path (using defaults if file is absent),
// then overlays secrets from environment variables.
func Load(path string) (*Config, error) {
	return LoadWithEnv(path)
}

// LoadWithEnv reads config from path then overrides specific sensitive fields
// from environment variables so secrets never need to appear in config files.
//
// Env var precedence (highest → lowest): env var > config file > default.
func LoadWithEnv(path string) (*Config, error) {
	cfg := Defaults

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnvOverrides(&cfg)
			return &cfg, nil // use defaults
		}
		return nil, err
	}
	defer f.Close()

	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	applyEnvOverrides(&cfg)
	return &cfg, nil
}

// applyEnvOverrides overlays environment variables onto cfg.
// Only specific fields are covered; all others remain as loaded from YAML.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("VIGILO_TELEGRAM_BOT_TOKEN"); v != "" {
		if cfg.Alerter.Telegram == nil {
			cfg.Alerter.Telegram = &TelegramConfig{}
		}
		cfg.Alerter.Telegram.BotToken = v
	}
	if v := os.Getenv("VIGILO_TELEGRAM_CHAT_ID"); v != "" {
		if cfg.Alerter.Telegram == nil {
			cfg.Alerter.Telegram = &TelegramConfig{}
		}
		cfg.Alerter.Telegram.ChatID = v
	}
	if v := os.Getenv("VIGILO_SLACK_WEBHOOK_URL"); v != "" {
		if cfg.Alerter.Slack == nil {
			cfg.Alerter.Slack = &SlackConfig{}
		}
		cfg.Alerter.Slack.WebhookURL = v
	}
	if v := os.Getenv("VIGILO_SMTP_PASSWORD"); v != "" {
		if cfg.Alerter.Email == nil {
			cfg.Alerter.Email = &EmailConfig{}
		}
		cfg.Alerter.Email.Password = v
	}
	if v := os.Getenv("VIGILO_WEB_TOKEN"); v != "" {
		cfg.WebToken = v
	}
	if v := os.Getenv("VIGILO_MCP_TOKEN"); v != "" {
		cfg.MCPToken = v
	}
}
