package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/voltagebots/vigilo/internal/collector"
)

// SlackConfig uses an incoming webhook URL — no bot token required.
// Create one at: https://api.slack.com/apps → Incoming Webhooks
type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

type slackChannel struct {
	cfg    *SlackConfig
	client *http.Client
}

func newSlackChannel(cfg *SlackConfig, client *http.Client) *slackChannel {
	return &slackChannel{cfg: cfg, client: client}
}
func (s *slackChannel) name() string { return "slack" }

func (s *slackChannel) send(e collector.Event, _ string) error {
	payload := slackPayload(e)
	b, _ := json.Marshal(payload)
	resp, err := s.client.Post(s.cfg.WebhookURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook: status %d", resp.StatusCode)
	}
	return nil
}

func slackPayload(e collector.Event) map[string]any {
	emoji := severityEmoji(e.Severity)
	resource := notificationText(e.Resource)
	action := notificationText(e.Action)
	source := notificationText(string(e.Source))
	payload := map[string]any{
		"text": fmt.Sprintf("%s [%s] %s -> %s (%s)",
			emoji, strings.ToUpper(string(e.Severity)),
			action, resource, source),
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{
					"type": "plain_text",
					"text": fmt.Sprintf(
						"%s Vigilo Immediate Alert -- %s\nAction: %s\nResource: %s\nSource: %s%s",
						emoji,
						strings.ToUpper(string(e.Severity)),
						action, resource, source,
						func() string {
							if e.Process != "" {
								context := fmt.Sprintf("\nProcess: %s (pid %d)", notificationText(e.Process), e.PID)
								if e.PPID > 0 {
									context += fmt.Sprintf("\nParent PID: %d", e.PPID)
								}
								if e.Executable != "" {
									context += fmt.Sprintf("\nExecutable: %s", notificationText(e.Executable))
								}
								if e.User != "" {
									context += fmt.Sprintf("\nUser ID: %s", notificationText(e.User))
								}
								return context
							}
							return ""
						}(),
					),
				},
			},
		},
	}
	return payload
}

func severityEmoji(sev collector.Severity) string {
	switch sev {
	case collector.SeverityCritical:
		return "[CRITICAL]"
	case collector.SeverityHigh:
		return "[HIGH]"
	case collector.SeverityMedium:
		return "[MEDIUM]"
	default:
		return "[INFO]"
	}
}
