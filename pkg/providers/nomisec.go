package providers

import (
	"encoding/json"
	"openpoc/pkg/types"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"strings"
)

func IsNomisec(candidateFilePath string) bool {
	return filepath.Ext(candidateFilePath) == ".json" && strings.Contains(filepath.Base(candidateFilePath), "CVE-")
}

func ParseNomicsec(jsonFilePath string) ([]*types.Nomisec, error) {
	fileName := filepath.Base(jsonFilePath)
	cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	file, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return nil, err
	}

	var data []*types.Nomisec
	err = json.Unmarshal(file, &data)
	if err != nil {
		return nil, err
	}

	for _, repo := range data {
		repo.CveId = utils.CleanCVE(cveID)
	}

	return data, nil
}
