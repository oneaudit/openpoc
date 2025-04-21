package utils

import "regexp"

var (
	cveMatcher = regexp.MustCompile(`^CVE-(\d{4})-\d{4,}$`)
)

func GetCVEYear(cve string) string {
	matches := cveMatcher.FindStringSubmatch(cve)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}
