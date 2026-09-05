package api

import (
	"regexp"
	"strings"
)

// Shared input-validation helpers for the identity server. Every handler that
// accepts free-text input (emails, names, org names) must run its fields
// through these so script payloads can never be stored or echoed back.
// The rules mirror the product's admin-catalog rules in the TerraSell api
// package; the email rule here is deliberately the tightest gate.

var (
	// emailRe accepts a pragmatic email shape with a strict local part:
	// no spaces, quotes, angle brackets, backticks, semicolons or control
	// characters — so "<script>…@x" family payloads can never pass.
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

	// lettersOnlyRe allows letters (incl. accented) plus spaces and benign
	// name punctuation. No digits and no symbols like ; / + < > " ` etc.
	lettersOnlyRe = regexp.MustCompile(`^[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'\-&()]{0,119}$`)

	// safeTextRe allows letters, digits, spaces and benign punctuation.
	// Every markup/script symbol (<>"`\;{}=) is rejected.
	safeTextRe = regexp.MustCompile(`^[A-Za-z0-9À-ÿ .,'/()&#%:+\-]{0,199}$`)

	// slugRe validates a URL slug: lowercase letters, digits and single
	// internal dashes.
	slugRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// validEmail reports whether s is a plausible, script-free email address.
func validEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	return emailRe.MatchString(s)
}

// lettersOnly reports whether s is a clean display name: letters, spaces and
// safe punctuation only.
func lettersOnly(s string) bool {
	return lettersOnlyRe.MatchString(s)
}

// safeText reports whether s avoids markup/script symbols on free-text fields
// such as organization names.
func safeText(s string) bool {
	return safeTextRe.MatchString(s)
}

// validSlug reports whether s is a safe URL slug.
func validSlug(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	return slugRe.MatchString(s)
}

// hasScriptMarker reports whether s still carries any markup-ish sequence even
// after the regex gates. Callers use it as a final hard stop.
func hasScriptMarker(s string) bool {
	lower := strings.ToLower(s)
	for _, marker := range []string{"<script", "</", "javascript:", "onerror=", "onload=", "&#", "\\u"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}