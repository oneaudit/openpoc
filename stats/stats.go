package main

import (
	"fmt"
	"io/fs"
	"net/url"
	"openpoc/pkg/stats"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"
)

const scoreboardTop = 10
const domainTop = 3

func getDirectories() (dirs []string) {
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
					fmt.Printf("Error browsing %s: %v\n", path, err)
					return nil
				}
				if info.Mode().IsRegular() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
					fileJobs <- stats.FileJob{Path: path, Folder: folder, CVE: strings.TrimSuffix(info.Name(), ".json")}
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

	aggStats := make(map[string]*stats.Stats)
	for r := range results {
		if _, ok := aggStats[r.FileJob.Folder]; !ok {
			aggStats[r.FileJob.Folder] = &stats.Stats{Year: r.FileJob.Folder}
			aggStats[r.FileJob.Folder].DomainMap = make(map[string]int)
		}
		cveStats := stats.CVEStat{CveID: r.FileJob.CVE, ExploitCount: len(r.Result.Openpoc)}
		aggStats[r.FileJob.Folder].CVECount += 1
		aggStats[r.FileJob.Folder].ExploitCount += cveStats.ExploitCount
		aggStats[r.FileJob.Folder].CveScoreBoard = append(aggStats[r.FileJob.Folder].CveScoreBoard, cveStats)

		for _, poc := range r.Result.Openpoc {
			parsedUrl, err := url.Parse(poc.URL)
			if err != nil {
				continue
			}
			domain := parsedUrl.Host
			if _, ok := aggStats[r.FileJob.Folder].DomainMap[domain]; !ok {
				aggStats[r.FileJob.Folder].DomainMap[domain] = 0
			}
			aggStats[r.FileJob.Folder].DomainMap[domain] += 1
		}
	}

	for _, stat := range aggStats {
		// Compute Frequencies
		if stat.CVECount > 0 {
			stat.ExploitCountAverage = float64(stat.ExploitCount) / float64(stat.CVECount)
		}
		// Compute CveScoreBoard
		sort.Slice(stat.CveScoreBoard, func(i, j int) bool {
			return stat.CveScoreBoard[i].ExploitCount > stat.CveScoreBoard[j].ExploitCount
		})
		if len(stat.CveScoreBoard) > scoreboardTop {
			stat.CveScoreBoard = stat.CveScoreBoard[:scoreboardTop]
		}
		// Compute Top URLs
		var counts []stats.DomainCount
		for d, count := range stat.DomainMap {
			counts = append(counts, stats.DomainCount{Domain: d, Count: count})
		}
		sort.Slice(counts, func(i, j int) bool {
			return counts[i].Count > counts[j].Count
		})
		if len(counts) > domainTop {
			counts = counts[:domainTop]
		}
		stat.DomainScoreBoard = counts
	}

	// Statistics computed for year: 1999
	// Total CVEs with an exploit: 568
	// Total Exploit Count: 827
	// Exploit Count Average: 1.455986
	// Top 10 CVEs with the most exploits:
	//  - 1. CVE: CVE-1999-0502, Exploit Count: 26
	//  - 2. CVE: CVE-1999-0016, Exploit Count: 7
	//  - 3. CVE: CVE-1999-0874, Exploit Count: 7
	//  - 4. CVE: CVE-1999-1053, Exploit Count: 6
	//  - 5. CVE: CVE-1999-0504, Exploit Count: 6
	//  - 6. CVE: CVE-1999-0040, Exploit Count: 5
	//  - 7. CVE: CVE-1999-0977, Exploit Count: 5
	//  - 8. CVE: CVE-1999-0767, Exploit Count: 5
	//  - 9. CVE: CVE-1999-0153, Exploit Count: 4
	//  - 10. CVE: CVE-1999-1510, Exploit Count: 4
	for year, stat := range aggStats {
		fmt.Println("Statistics computed for year:", year)
		fmt.Printf("Total CVEs with an exploit: %d\n", stat.CVECount)
		fmt.Printf("Total Exploit Count: %d\n", stat.ExploitCount)
		fmt.Printf("Exploit Count Average: %f\n", stat.ExploitCountAverage)
		fmt.Println("Top 10 CVEs with the most exploits:")
		for i := 0; i < scoreboardTop && i < len(stat.CveScoreBoard); i++ {
			entry := stat.CveScoreBoard[i]
			fmt.Printf("%d. CVE: %s, Exploit Count: %d\n",
				i+1, entry.CveID, entry.ExploitCount)
		}
		fmt.Println("Top 3 CVEs with the most exploits:")
		for i := 0; i < domainTop && i < len(stat.DomainScoreBoard); i++ {
			entry := stat.DomainScoreBoard[i]
			fmt.Printf("%d. Domain: %s, Count: %d\n",
				i+1, entry.Domain, entry.Count)
		}
		fmt.Println()
	}

	templateFileName := "stats/stats_example.svg"
	tmpl, err := template.ParseFiles(templateFileName)
	if err != nil {
		fmt.Printf("Could not open template file %s: %v\n", templateFileName, err)
		return
	}

	for year, stat := range aggStats {
		outputFileName := fmt.Sprintf("%s.svg", year)
		outputFile, err := os.Create(".github/images/" + outputFileName)
		if err != nil {
			fmt.Printf("Could not open output file %s: %v\n", outputFileName, err)
			break
		}
		err = tmpl.Execute(outputFile, stat)
		if err != nil {
			fmt.Printf("Could not open run template on file %s: %v\n", outputFileName, err)
		}
		outputFile.Close()
	}

	fmt.Println(time.Now().String())
}
