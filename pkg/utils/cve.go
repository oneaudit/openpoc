package utils

import (
	"regexp"
	"strings"
)

var (
	cveMatcher = regexp.MustCompile(`^CVE-(\d{4})-\d{4,}$`)
)

func CleanCVE(cve string) string {
	return strings.Replace(
		strings.Replace(
			strings.Replace(cve, " ", "", -1),
			"‑", "-", -1,
		),
		"–", "-", -1,
	)
}

func GetCVEYear(cve string) string {
	matches := cveMatcher.FindStringSubmatch(cve)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}
