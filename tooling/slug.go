package tooling

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrSlugTaken = errors.New("an organization with that slug already exists")
	slugStrip    = regexp.MustCompile(`[^a-z0-9]+`)
)

func Slugify(name string) string {
	slug := strings.Trim(slugStrip.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(slug) > 100 {
		slug = slug[:100]
	}
	if slug == "" {
		slug = "business"
	}
	return slug
}
