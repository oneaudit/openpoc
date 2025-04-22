package main

import (
	"fmt"
	"io/fs"
	"openpoc/pkg/stats"
	"openpoc/pkg/types"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	fmt.Println(time.Now().String())

	var wg sync.WaitGroup
	dirToScan := "1999"
	fileJobs := make(chan stats.FileJob, 100)
	results := make(chan *types.AggregatorResult, 100)
	numWorkers := 8
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go stats.Worker(i, fileJobs, results, &wg)
	}
	var walkWg sync.WaitGroup
	walkWg.Add(1)

	go func() {
		defer walkWg.Done()
		err := filepath.Walk(dirToScan, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				fmt.Printf("Error accessing %s: %v\n", path, err)
				return nil
			}
			if info.Mode().IsRegular() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
				fileJobs <- stats.FileJob{Path: path}
			}
			return nil
		})
		if err != nil {
			fmt.Printf("Error walking the directory: %v\n", err)
		}
	}()

	go func() {
		walkWg.Wait()
		close(fileJobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var s stats.Stats
	s.CategoryCounters = make(map[string]int)
	for _ = range results {
		s.TotalFiles++
	}

	// Output the computed s.
	fmt.Println("Statistics computed from folder:", dirToScan)
	fmt.Printf("Total Files Processed: %d\n", s.TotalFiles)
	fmt.Printf("Total Value Sum: %.2f\n", s.TotalValue)
	fmt.Printf("Total Count Sum: %d\n", s.TotalCount)

	fmt.Println(time.Now().String())
}
