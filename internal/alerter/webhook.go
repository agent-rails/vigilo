package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

// WebhookConfig posts a JSON payload to any HTTP endpoint.
// Useful for PagerDuty, OpsGenie, custom SIEM integrations, etc.
type WebhookConfig struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"` // e.g. Authorization: Bearer ...
}

type webhookChannel struct {
	cfg    *WebhookConfig
	client *http.Client
}

func newWebhookChannel(cfg *WebhookConfig, client *http.Client) *webhookChannel {
	return &webhookChannel{cfg: cfg, client: client}
}
func (w *webhookChannel) name() string { return "webhook:" + w.cfg.Name }

func (w *webhookChannel) send(e collector.Event, _ string) error {
	payload := map[string]any{
		"source":     string(e.Source),
		"timestamp":  e.Timestamp.UTC().Format(time.RFC3339),
		"action":     e.Action,
		"resource":   e.Resource,
		"severity":   string(e.Severity),
		"process":    e.Process,
		"executable": e.Executable,
		"pid":        e.PID,
		"ppid":       e.PPID,
		"user_id":    e.User,
		"detail":     e.Detail,
	}
	b, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, w.cfg.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s: status %d", w.cfg.Name, resp.StatusCode)
	}
	return nil
}
