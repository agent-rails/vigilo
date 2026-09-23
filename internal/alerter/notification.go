package alerter

import (
	"strings"
	"unicode"
)

const maxNotificationRunes = 512

// notificationText keeps attacker-controlled event fields on one line and
// removes control characters before they enter external alert formats.
func notificationText(value string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	runes := []rune(clean)
	if len(runes) > maxNotificationRunes {
		return string(runes[:maxNotificationRunes]) + "…"
	}
	return clean
}

func cefHeader(value string) string {
	value = notificationText(value)
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, "|", `\|`)
}

func cefExtension(value string) string {
	value = notificationText(value)
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "=", `\=`)
	return strings.ReplaceAll(value, "|", `\|`)
}
