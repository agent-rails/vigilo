package alerter

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

// EmailConfig configures SMTP delivery.
// Works with Gmail (smtp.gmail.com:587), SendGrid, Mailgun, AWS SES, etc.
type EmailConfig struct {
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"` // 587 (STARTTLS) or 465 (TLS)
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type emailChannel struct {
	cfg *EmailConfig
}

func newEmailChannel(cfg *EmailConfig) *emailChannel { return &emailChannel{cfg: cfg} }
func (e *emailChannel) name() string                 { return "email" }

func (ec *emailChannel) send(ev collector.Event, body string) error {
	sev := strings.ToUpper(string(ev.Severity))
	subject := fmt.Sprintf("[Vigilo] %s Alert: %s %s", sev, ev.Action, ev.Resource)

	msg := strings.Join([]string{
		"From: " + ec.cfg.From,
		"To: " + strings.Join(ec.cfg.To, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
		"",
		"--",
		"Vigilo Security Daemon",
		ev.Timestamp.UTC().Format(time.RFC3339),
	}, "\r\n")

	port := ec.cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", ec.cfg.SMTPHost, port)
	auth := smtp.PlainAuth("", ec.cfg.Username, ec.cfg.Password, ec.cfg.SMTPHost)

	if port == 465 {
		return ec.sendTLS(addr, auth, msg)
	}

	// Dial with 15s timeout before handing off to smtp.SendMail.
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	c, err := smtp.NewClient(conn, ec.cfg.SMTPHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Close()

	if err = c.StartTLS(&tls.Config{ServerName: ec.cfg.SMTPHost}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	if err = c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err = c.Mail(ec.cfg.From); err != nil {
		return err
	}
	for _, to := range ec.cfg.To {
		if err = c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = fmt.Fprint(w, msg); err != nil {
		return err
	}
	return w.Close()
}

func (ec *emailChannel) sendTLS(addr string, auth smtp.Auth, msg string) error {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}

	tlsCfg := &tls.Config{ServerName: ec.cfg.SMTPHost}
	conn := tls.Client(rawConn, tlsCfg)
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return fmt.Errorf("smtp tls handshake: %w", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, ec.cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer c.Close()

	if err = c.Auth(auth); err != nil {
		return err
	}
	if err = c.Mail(ec.cfg.From); err != nil {
		return err
	}
	for _, to := range ec.cfg.To {
		if err = c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, msg)
	if err != nil {
		return err
	}
	return w.Close()
}
