package alerter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/voltagebots/vigilo/internal/collector"
)

func TestSlackUsesPlainTextForUntrustedEventFields(t *testing.T) {
	payload := slackPayload(collector.Event{
		Source: collector.SourceFile, Severity: collector.SeverityHigh,
		Action: "write", Resource: "</code>\n@here `injected`", Process: "tool<admin>",
	})
	if _, err := json.Marshal(payload); err != nil {
		t.Fatalf("payload not JSON-safe: %v", err)
	}
	blocks := payload["blocks"].([]map[string]any)
	blockText := blocks[0]["text"].(map[string]any)
	if blockText["type"] != "plain_text" {
		t.Fatalf("untrusted text rendered as markup: %#v", blockText)
	}
	if strings.Contains(blockText["text"].(string), "\n@here") {
		t.Fatal("newline in event field was not neutralized")
	}
}

func TestTelegramEscapesUntrustedEventFields(t *testing.T) {
	message := telegramMessage(collector.Event{
		Source: collector.SourceFile, Severity: collector.SeverityHigh,
		Action: "write</code>", Resource: "<b>owned</b> & \"file\"",
		Process: "<admin>", Executable: "/tmp/<payload>", Detail: "<i>detail</i>",
	})
	for _, unsafe := range []string{"<b>owned</b>", "<admin>", "<i>detail</i>"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("raw HTML field %q in Telegram message: %s", unsafe, message)
		}
	}
	for _, escaped := range []string{"&lt;b&gt;owned&lt;/b&gt;", "&lt;admin&gt;", "&lt;i&gt;detail&lt;/i&gt;"} {
		if !strings.Contains(message, escaped) {
			t.Fatalf("escaped field %q missing from Telegram message: %s", escaped, message)
		}
	}
}

func TestCEFFieldsEscapeSeparatorsAndControls(t *testing.T) {
	if got := cefHeader("bad|name\nnext"); got != `bad\|name next` {
		t.Fatalf("CEF header escaping = %q", got)
	}
	if got := cefExtension("x=y|z\\q\nnext"); got != `x\=y\|z\\q next` {
		t.Fatalf("CEF extension escaping = %q", got)
	}
}

func TestNotificationFieldsAreBounded(t *testing.T) {
	got := notificationText(strings.Repeat("x", maxNotificationRunes+20))
	if len([]rune(got)) != maxNotificationRunes+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("notification field not bounded: %d runes", len([]rune(got)))
	}
}

func TestEmailSubjectCannotInjectHeaders(t *testing.T) {
	subject := emailSubject(collector.Event{
		Severity: collector.SeverityHigh,
		Action:   "write\r\nBcc: victim@example.com",
		Resource: "/tmp/secret\nSubject: forged",
	})
	if strings.ContainsAny(subject, "\r\n") {
		t.Fatalf("email subject permits header injection: %q", subject)
	}
}
