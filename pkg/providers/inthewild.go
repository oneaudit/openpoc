package providers

import (
	"encoding/json"
	"openpoc/pkg/types"
	"openpoc/pkg/utils"
	"os"
)

func ParseInTheWild(jsonFilePath string) ([]*types.InTheWild, error) {
	file, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return nil, err
	}

	var data []*types.InTheWild
	err = json.Unmarshal(file, &data)
	if err != nil {
		return nil, err
	}

	var final []*types.InTheWild
	for _, candidate := range data {
		candidate.CveID = utils.CleanCVE(candidate.CveID)
		candidate.ReportURL, candidate.Trustworthy = InspectAggregatorURL(candidate.ReportURL, candidate.CveID, true)
		if candidate.ReportURL != "" {
			final = append(final, candidate)
		}
	}

	return final, nil
}
