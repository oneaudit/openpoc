package main

import (
	"fmt"
	"io/fs"
	"openpoc/pkg/stats"
	"openpoc/pkg/types"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func getDirectories() (dirs []string) {
	startYear := 1999
	currentYear := 2001 //time.Now().Year()
	for year := startYear; year <= currentYear; year++ {
		dir := fmt.Sprintf("%04d", year)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func main() {
	fmt.Println(time.Now().String())

	var wg sync.WaitGroup
	directories := getDirectories()

	fileJobs := make(chan stats.FileJob, 100)
	results := make(chan *types.AggregatorResult, 100)
	numWorkers := 8
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go stats.Worker(i, fileJobs, results, &wg)
	}
	var walkWg sync.WaitGroup

	for _, dir := range directories {
		walkWg.Add(1)
		go func(folder string) {
			defer walkWg.Done()
			err := filepath.Walk(folder, func(path string, info fs.FileInfo, err error) error {
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
				fmt.Printf("Error walking the directory %s: %v\n", folder, err)
			}
		}(dir)
	}

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
	fmt.Println("Statistics computed from folder:", directories)
	fmt.Printf("Total Files Processed: %d\n", s.TotalFiles)
	fmt.Printf("Total Value Sum: %.2f\n", s.TotalValue)
	fmt.Printf("Total Count Sum: %d\n", s.TotalCount)

	fmt.Println(time.Now().String())
}
