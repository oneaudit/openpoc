package providers

import (
	"encoding/json"
	providertypes "openpoc/pkg/types/public"
	"openpoc/pkg/utils"
	"os"
)

func ParseInTheWild(jsonFilePath string) ([]*providertypes.InTheWild, error) {
	file, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return nil, err
	}

	var data []*providertypes.InTheWild
	err = json.Unmarshal(file, &data)
	if err != nil {
		return nil, err
	}

	var final []*providertypes.InTheWild
	for _, candidate := range data {
		candidate.CveID = utils.CleanCVE(candidate.CveID)
		candidate.ReportURL, candidate.Score = InspectAggregatorURL(candidate.ReportURL, candidate.CveID, true)
		if candidate.ReportURL != "" {
			final = append(final, candidate)
		}
	}

	return final, nil
}
