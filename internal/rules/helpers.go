package rules

import (
	"strconv"
	"strings"
)

// parseTimeSeconds accepts OpenSSH-style time values like "30", "30s",
// "1m", "1h", returning the value in seconds (best effort; 0 on parse fail).
func parseTimeSeconds(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := 1
	switch s[len(s)-1] {
	case 's', 'S':
		s = s[:len(s)-1]
	case 'm', 'M':
		s = s[:len(s)-1]
		mult = 60
	case 'h', 'H':
		s = s[:len(s)-1]
		mult = 3600
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n * mult
}

func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}
