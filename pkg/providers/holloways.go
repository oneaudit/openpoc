package providers

import (
	"encoding/json"
	providertypes "openpoc/pkg/types/public"
	"os"
)

func ParseHolloways(jsonFilePath string) (data []*providertypes.Holloways, err error) {
	file, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return nil, err
	}
	// Fill both data and error
	err = json.Unmarshal(file, &data)
	return
}
