package utils

import (
	"fmt"
	"io/fs"
	"openpoc/pkg/types"
	"os"
	"path/filepath"
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

func ProcessFiles[T any](rootDir string, _ int, processFile types.ProcessFunction[T]) ([]*T, error) {
	var finalResults []*T
	err := filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error browsing %s: %v", path, err)
		}

		if info.Mode().IsRegular() {
			job := types.FileJob{Path: path, Folder: rootDir, FileInfo: info}
			results, err := processFile(job)
			if err != nil {
				return err
			}
			for _, result := range results {
				finalResults = append(finalResults, result)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking the directory %s: %v", rootDir, err)
	}
	return finalResults, nil
}
