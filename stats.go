package main

import (
	"fmt"
	"io/fs"
	"openpoc/pkg/stats"
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
	results := make(chan *stats.StatResult, 100)
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
					fmt.Printf("Error accessing %aggStats: %v\n", path, err)
					return nil
				}
				if info.Mode().IsRegular() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
					fileJobs <- stats.FileJob{Path: path, Folder: folder}
				}
				return nil
			})
			if err != nil {
				fmt.Printf("Error walking the directory %aggStats: %v\n", folder, err)
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

	aggStats := make(map[string]*stats.Stats)
	for r := range results {
		if _, ok := aggStats[r.FileJob.Folder]; !ok {
			aggStats[r.FileJob.Folder] = &stats.Stats{}
		}
		aggStats[r.FileJob.Folder].CVECount += 1
		aggStats[r.FileJob.Folder].ExploitCount += len(r.Result.Openpoc)
	}

	for _, stat := range aggStats {
		if stat.CVECount > 0 {
			stat.ExploitCountAverage = float64(stat.ExploitCount) / float64(stat.CVECount)
		}
	}

	for year, stat := range aggStats {
		fmt.Println("Statistics computed for year:", year)
		fmt.Printf("Total CVEs with an exploit: %d\n", stat.CVECount)
		fmt.Printf("Total Exploit Count: %d\n", stat.ExploitCount)
		fmt.Printf("Exploit Count Average: %f\n", stat.ExploitCountAverage)
		fmt.Println()
	}

	fmt.Println(time.Now().String())
}
