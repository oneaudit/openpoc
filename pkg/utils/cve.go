package utils

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	cveMatcher          = regexp.MustCompile(`^CVE-(\d{4})-\d{4,}$`)
	cveBadParserMatcher = regexp.MustCompile(`CVE-(\d{4})-(\d{1,3})$`)
)

func CleanCVE(cve string) string {
	cve = strings.Replace(
		strings.Replace(
			strings.Replace(cve, " ", "", -1),
			"‑", "-", -1,
		),
		"–", "-", -1,
	)
	cve = cveBadParserMatcher.ReplaceAllStringFunc(cve, func(match string) string {
		parts := cveBadParserMatcher.FindStringSubmatch(match)
		if len(parts) > 2 {
			year := parts[1]
			number := parts[2]
			if len(number) < 4 {
				return fmt.Sprintf("CVE-%s-0%s", year, number)
			}
		}
		return match
	})
	return strings.TrimSpace(cve)
}

func GetCVEYear(cve string) string {
	matches := cveMatcher.FindStringSubmatch(cve)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}
