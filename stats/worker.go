package main

import (
	"encoding/json"
	"fmt"
	"openpoc/pkg/types"
	"os"
	"sync"
)

func processFile(fileJob FileJob) (*StatResult, error) {
	bytes, err := os.ReadFile(fileJob.Path)
	if err != nil {
		return nil, err
	}
	var result types.AggregatorResult
	if err = json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	var statResult StatResult
	statResult.FileJob = fileJob
	statResult.Result = &result
	return &statResult, nil
}

func Worker(id int, jobs <-chan FileJob, results chan<- *StatResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		res, err := processFile(job)
		if err != nil {
			fmt.Printf("[Worker %d] Error processing %s: %v\n", id, job.Path, err)
			continue
		}
		results <- res
	}
}
