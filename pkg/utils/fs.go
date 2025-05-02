package utils

import (
	"context"
	"fmt"
	"io/fs"
	"openpoc/pkg/types"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func WasModifiedWithin(filePath string, duration time.Duration) bool {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	modTime := fileInfo.ModTime()
	currentTime := time.Now()
	diff := currentTime.Sub(modTime)
	return diff <= (duration-1)*time.Hour
}

func GetDirectories() (dirs []string) {
	currentYear := time.Now().Year()
	startYear := 1999
	for year := currentYear; year >= startYear; year-- {
		dir := fmt.Sprintf("%04d", year)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func ProcessFiles[T any](rootDir string, numWorkers int, processFile types.ProcessFunction[T]) ([]*T, error) {
	var wg sync.WaitGroup
	var exploits []*T
	fileJobs := make(chan types.FileJob, 100)
	results := make(chan *T, 100)
	errors := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker[T](ctx, fileJobs, results, errors, &wg, processFile)
	}

	go func() {
		for result := range results {
			exploits = append(exploits, result)
		}
	}()

	err := filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error browsing %s: %v", path, err)
		}

		if info.Mode().IsRegular() {
			for _, t := range []string{
				"CVE-2025-3102.json",
				"CVE-2025-29810.json",
				"CVE-2025-29927.json",
				"CVE-2025-30065.json",
				"CVE-2025-30066.json",
				"CVE-2025-30144.json",
				"CVE-2025-30208.json",
				"CVE-2025-30216.json",
				"CVE-2025-30349.json",
				"CVE-2025-30406.json",
				"CVE-2025-30567.json",
			} {
				if strings.HasSuffix(path, t) {
					fmt.Printf("[%s] Found from iterator.\n", path)
					break
				}
			}
			fileJobs <- types.FileJob{Path: path, Folder: rootDir, FileInfo: info}
		}
		return nil
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error walking the directory %s: %v", rootDir, err)
	}

	go func() {
		wg.Wait()
		close(fileJobs)
		close(results)
		close(errors)
	}()

	select {
	case err = <-errors:
		cancel()
		return nil, fmt.Errorf("error received by runner for %s: %v", rootDir, err)
	default:
		cancel()
		for result := range results {
			exploits = append(exploits, result)
		}
		return exploits, nil
	}
}

func worker[T any](ctx context.Context, fileJobs <-chan types.FileJob, final chan<- *T, errors chan<- error, wg *sync.WaitGroup, processFile types.ProcessFunction[T]) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done(): // stop on cancelled
			return
		case job, ok := <-fileJobs:
			if !ok { // done
				fmt.Println("file job channel closed")
				return
			}

			results, err := processFile(job)
			if err != nil {
				errors <- err
				return
			}
			for _, result := range results {
				final <- result
			}
		}
	}
}
