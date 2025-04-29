package providers

import (
	"fmt"
	"openpoc/pkg/types"
	providertypes "openpoc/pkg/types/public"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// The simplest example is: ['CVE', 'XXXX-XXXX']
var msfCveMatcher = regexp.MustCompile(`\[\s*'CVE'\s*,\s*'(\d{4}-\d{4,})'\s*]`)

func IsMetasploit(candidateFilePath string) bool {
	// Skip example files and non-ruby files
	return filepath.Ext(candidateFilePath) == ".rb" && !strings.Contains(filepath.Base(candidateFilePath), "example")
}

func ParseMetasploit(rootDir string, rubyFilePath string, cache *sync.Map) ([]*providertypes.Metasploit, error) {
	content, err := os.ReadFile(rubyFilePath)
	if err != nil {
		return nil, err
	}

	// extract CVEs
	text := string(content)
	matches := msfCveMatcher.FindAllStringSubmatch(text, -1)
	if matches == nil || len(matches) == 0 {
		return nil, nil
	}

	// relative path
	relativePath, err := filepath.Rel(rootDir, rubyFilePath)
	if err != nil {
		return nil, err
	}
	relativePath = filepath.ToSlash(relativePath)

	// date
	addedAt := utils.GetDateFromGitFile(rootDir, relativePath, cache, types.DefaultDate)

	cves := make(map[string]*providertypes.Metasploit)
	for _, submatches := range matches {
		if len(submatches) != 2 {
			continue
		}
		cveId := utils.CleanCVE("CVE-" + submatches[1])
		cves[cveId] = &providertypes.Metasploit{
			CveID:        cveId,
			URL:          fmt.Sprintf("https://github.com/rapid7/metasploit-framework/blob/master/%s", relativePath),
			TemplatePath: relativePath,
			AddedAt:      addedAt,
		}
	}

	var results []*providertypes.Metasploit
	for _, cve := range cves {
		results = append(results, cve)
	}
	return results, nil
}
