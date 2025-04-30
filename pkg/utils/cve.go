package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	cveMatcher          = regexp.MustCompile(`^CVE-(\d{4})-(\d{4,})$`)
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
	return strings.TrimSpace(strings.ToUpper(cve))
}

func GetCvePartsAsInt(cve string) (int64, int64) {
	matches := cveMatcher.FindStringSubmatch(cve)
	if len(matches) == 3 {
		year, _ := strconv.ParseInt(matches[1], 10, 64)
		rid, _ := strconv.ParseInt(matches[2], 10, 64)
		return year, rid
	}
	return 0, 0
}

func GetCVEYear(cve string) string {
	matches := cveMatcher.FindStringSubmatch(cve)
	if len(matches) == 3 {
		return matches[1]
	}
	return ""
}
