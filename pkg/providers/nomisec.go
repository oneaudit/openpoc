package providers

import (
	"encoding/json"
	"fmt"
	providertypes "openpoc/pkg/types/public"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"strings"
)

var NomisecMissing = []string{
	"CVE-2025-3102.json",
	"CVE-2025-29810.json",
	"CVE-2025-29927.json",
	"CVE-2025-30065.json",
	"CVE-2025-30066.json",
	"CVE-2025-30144.json",
	"CVE-2025-30208.json",
	"CVE-2025-30216.json",
	"CVE-2025-30349.json",
	"CVE-2025-30406.json",
	"CVE-2025-30567.json",
}

func IsNomisec(candidateFilePath string) bool {
	return filepath.Ext(candidateFilePath) == ".json" && strings.Contains(filepath.Base(candidateFilePath), "CVE-")
}

func ParseNomicsec(jsonFilePath string) ([]*providertypes.Nomisec, error) {
	var enableDebug bool
	for _, missing := range NomisecMissing {
		if strings.HasSuffix(jsonFilePath, missing) {
			fmt.Printf("Nomisec missing found: %s\n", jsonFilePath)
			enableDebug = true
			break
		}
	}

	fileName := filepath.Base(jsonFilePath)
	cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	file, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return nil, err
	}

	var data []*providertypes.Nomisec
	err = json.Unmarshal(file, &data)
	if err != nil {
		return nil, err
	}

	if enableDebug {
		fmt.Printf("[%s] Nomisec parsing %s: %d\n", jsonFilePath, cveID, len(data))
	}

	for _, repo := range data {
		repo.CveId = cleanNomisecCVE(cveID)
	}

	return data, nil
}

func cleanNomisecCVE(cve string) string {
	// A few errors in NomiSec
	if cve == "CVE-2017-75" {
		cve = "CVE-2017-7529"
	} else if cve == "CVE-2018-14" {
		cve = "CVE-2018-14773"
	} else if cve == "CVE-2021-22" {
		cve = "CVE-2021-22555"
	} else if cve == "CVE-2023-08" {
		cve = "CVE-2022-31470"
	}
	return utils.CleanCVE(cve)
}
