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
	addedURLs := make(map[string]struct{})
	for _, candidate := range data {
		candidate.CveID = utils.CleanCVE(candidate.CveID)
		candidate.ReportURL, candidate.Score = InspectAggregatorURL(candidate.ReportURL, candidate.CveID, true)
		if candidate.ReportURL != "" {
			if _, exists := addedURLs[candidate.ReportURL]; exists {
				continue
			}
			// Only add URLs once
			addedURLs[candidate.ReportURL] = struct{}{}
			// Add to the list
			final = append(final, candidate)
		}
	}

	return final, nil
}
