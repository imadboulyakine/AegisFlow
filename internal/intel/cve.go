package intel

import (
	"fmt"
	"strings"
	"time"
)

// maxCVESequenceDigits bounds the sequence part of a CVE ID. The CVE format allows any number
// of digits (4+); real IDs use up to 7 today, so 19 leaves ample headroom while bounding input.
const maxCVESequenceDigits = 19

// NormalizeCVE trims and upper-cases s and reports whether it is a well-formed CVE identifier
// ("CVE-" + 4-digit year + "-" + 4 to 19 digits). The normalized form is the map key used
// throughout this package.
func NormalizeCVE(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > len("CVE-0000-")+maxCVESequenceDigits {
		return "", false
	}
	s = strings.ToUpper(s)
	rest, ok := strings.CutPrefix(s, "CVE-")
	if !ok {
		return "", false
	}
	year, seq, ok := strings.Cut(rest, "-")
	if !ok || len(year) != 4 || !allDigits(year) {
		return "", false
	}
	if len(seq) < 4 || len(seq) > maxCVESequenceDigits || !allDigits(seq) {
		return "", false
	}
	return s, true
}

func allDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// dateLayout is the calendar-date layout used by KEV (dateAdded, dueDate) and EPSS (date).
const dateLayout = time.DateOnly

// parseDate parses a "YYYY-MM-DD" date as midnight UTC.
func parseDate(s string) (time.Time, error) {
	return time.ParseInLocation(dateLayout, strings.TrimSpace(s), time.UTC)
}

// checkTime rejects instants whose UTC year falls outside 0..9999 (e.g. "9999-12-31T23:00:00-05:00"),
// which time.Time cannot marshal to JSON and no real feed produces.
func checkTime(name string, t time.Time) error {
	if y := t.UTC().Year(); y < 0 || y > 9999 {
		return fmt.Errorf("%s: year %d out of range", name, y)
	}
	return nil
}

// formatDate renders t as "YYYY-MM-DD", or "" for the zero time.
func formatDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(dateLayout)
}
