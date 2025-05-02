package utils

import (
	"fmt"
	"io/fs"
	"openpoc/pkg/types"
	"os"
	"path/filepath"
	"strings"
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
			for _, t := range []string{
				"CVE-2025-3102.json", "CVE-2025-29810.json", "CVE-2025-29927.json",
				"CVE-2025-30065.json", "CVE-2025-30066.json", "CVE-2025-30144.json",
				"CVE-2025-30208.json", "CVE-2025-30216.json", "CVE-2025-30349.json",
				"CVE-2025-30406.json", "CVE-2025-30567.json", "CVE-2025-31131.json",
				"CVE-2025-31137.json", "CVE-2025-31161.json", "CVE-2025-31200.json",
				"CVE-2025-31486.json", "CVE-2025-31650.json", "CVE-2025-31864.json",
				"CVE-2025-32395.json", "CVE-2025-3243.json", "CVE-2025-32432.json",
				"CVE-2025-3248.json", "CVE-2025-34028.json", "CVE-2025-3568.json",
				"CVE-2025-42599.json", "CVE-2025-43864.json", "CVE-2025-46657.json",
			} {
				if strings.HasSuffix(path, t) {
					fmt.Printf("[%s] Found from iterator.\n", path)
					break
				}
			}
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

	fmt.Println("We finished walking the folder.")
	if err != nil {
		return nil, fmt.Errorf("error walking the directory %s: %v", rootDir, err)
	}

	return finalResults, nil
}
