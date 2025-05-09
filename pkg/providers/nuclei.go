package providers

import (
	"fmt"
	"openpoc/pkg/types"
	providertypes "openpoc/pkg/types/public"
	"openpoc/pkg/utils"
	"path/filepath"
	"strings"
	"sync"
)

func IsNucleiTemplate(candidateFilePath string) bool {
	return filepath.Ext(candidateFilePath) == ".yaml" && strings.Contains(filepath.Base(candidateFilePath), "CVE-")
}

func ParseNucleiTemplate(rootDir string, yamlFilePath string, cache *sync.Map) ([]*providertypes.Nuclei, error) {
	fileName := filepath.Base(yamlFilePath)
	cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	// fix some template names not having the correct name
	cveIDParts := strings.Split(cveID, "-")
	if len(cveIDParts) > 3 {
		cveID = fmt.Sprintf("CVE-%s-%s", cveIDParts[1], cveIDParts[2])
	}
	cveID = utils.CleanCVE(cveID)

	relativePath, err := filepath.Rel(rootDir, yamlFilePath)
	if err != nil {
		return nil, err
	}
	relativePath = filepath.ToSlash(relativePath)

	return []*providertypes.Nuclei{
		{
			CveID:        cveID,
			URL:          fmt.Sprintf("https://github.com/projectdiscovery/nuclei-templates/blob/main/%s", relativePath),
			TemplatePath: relativePath,
			AddedAt:      utils.GetDateFromGitFile(rootDir, relativePath, cache, types.DefaultDate),
		},
	}, nil
}
