package stats

import (
	"encoding/json"
	"fmt"
	"openpoc/pkg/types"
	"os"
	"sync"
)

func processFile(filePath string) (*types.AggregatorResult, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var result types.AggregatorResult
	if err = json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func Worker(id int, jobs <-chan FileJob, results chan<- *types.AggregatorResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		res, err := processFile(job.Path)
		if err != nil {
			fmt.Printf("[Worker %d] Error processing %s: %v\n", id, job.Path, err)
			continue
		}
		results <- res
	}
}
