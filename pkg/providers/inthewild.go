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

	for _, d := range data {
		d.CveID = utils.CleanCVE(d.CveID)
	}

	return data, nil
}
