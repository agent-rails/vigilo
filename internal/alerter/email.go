package alerter

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
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

func emailSubject(ev collector.Event) string {
	sev := strings.ToUpper(string(ev.Severity))
	return mime.QEncoding.Encode("UTF-8", fmt.Sprintf("[Vigilo] %s Alert: %s %s", sev, notificationText(ev.Action), notificationText(ev.Resource)))
}

func (ec *emailChannel) send(ev collector.Event, body string) error {
	subject := emailSubject(ev)

	msg := strings.Join([]string{
		"From: " + notificationText(ec.cfg.From),
		"To: " + notificationText(strings.Join(ec.cfg.To, ", ")),
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
	addr := net.JoinHostPort(ec.cfg.SMTPHost, strconv.Itoa(port))
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
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
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
	_ = rawConn.SetDeadline(time.Now().Add(15 * time.Second))

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
