package providers

import (
	"bufio"
	"errors"
	"openpoc/pkg/types"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

func IsTrickestExploit(candidateFilePath string) bool {
	return filepath.Ext(candidateFilePath) == ".md" && strings.Contains(filepath.Base(candidateFilePath), "CVE-")
}

func ParseTrickest(markdownFilePath string) ([]*types.Trickest, error) {
	fileName := filepath.Base(markdownFilePath)
	cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	file, err := os.ReadFile(markdownFilePath)
	if err != nil {
		return nil, err
	}
	pocURLs := extractTrickestCVEPoCLinks(string(file))

	var records []*types.Trickest
	for _, url := range pocURLs {
		var trusted bool
		url, trusted = InspectAggregatorURL(url, cveID, false)
		if url != "" {
			records = append(records, &types.Trickest{
				CveID:       cleanTrickestCve(cveID),
				URL:         url,
				AddedAt:     types.DefaultDate,
				Trustworthy: trusted,
			})
		}
	}

	return records, nil
}

func ParseTrickestReferences(textFilePath string) (exploits []*types.Trickest, err error) {
	var file *os.File
	file, err = os.Open(textFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			err = errors.New("invalid trickest reference")
			return
		}
		cveId := cleanTrickestCve(parts[0])
		url, trusted := InspectAggregatorURL(parts[1], cveId, true)
		if url == "" {
			continue
		}
		exploits = append(exploits, &types.Trickest{
			CveID:       cveId,
			URL:         url,
			AddedAt:     types.DefaultDate,
			Trustworthy: trusted,
		})
	}

	if err = scanner.Err(); err != nil {
		return
	}
	return
}

func extractTrickestCVEPoCLinks(input string) (pocURLs []string) {
	lines := strings.Split(input, "\n")
	canScrap := false
	for _, line := range lines {
		if !canScrap && strings.HasPrefix(line, "### POC") {
			canScrap = true
		}
		if line == "" || line[0] != '-' {
			continue
		}
		line = strings.Split(strings.TrimSpace(line[1:]), " ")[0]
		if line == "" || !strings.HasPrefix(line, "http") {
			continue
		}
		if strings.HasPrefix(line, "https://") {
			line = line[8:]
		} else {
			line = line[7:]
		}
		// At this point, the output looks like a link
		pocURLs = append(pocURLs, line)
	}
	return
}

func cleanTrickestCve(cve string) string {
	if cve == "CVE-7600-2018" {
		cve = "CVE-2018-7600"
	}
	if cve == "CVE-2121-44228" {
		cve = "CVE-2021-44228"
	}
	return utils.CleanCVE(cve)
}
