package providers

import (
	"encoding/json"
	"openpoc/pkg/types"
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

	return data, nil
}
