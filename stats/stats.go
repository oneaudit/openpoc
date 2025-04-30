package main

import (
	"fmt"
	"io/fs"
	"net/url"
	"openpoc/pkg/providers"
	"openpoc/pkg/stats"
	"openpoc/pkg/types"
	"openpoc/pkg/types/public"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

const scoreboardTop = 10
const domainTop = 3
const urlTop = 3
const baseTemplate = `<svg xmlns="http://www.w3.org/2000/svg" width="{{.Width}}" height="20" role="img">
    <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
    <g>
        <rect width="{{.FirstX}}" height="20" fill="#555"/>
        <rect x="{{.FirstX}}" width="267" height="20" fill="{{.Color}}"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text x="{{.SecondX}}" y="140" transform="scale(.1)" fill="#fff">
            {{.Title}}
        </text>
        <text x="{{.ThirdX}}" y="140" transform="scale(.1)" fill="#333">
            {{.Value}}
        </text>
    </g>
</svg>`

type baseTemplateData struct {
	Title   string
	Value   string
	Width   int
	FirstX  int
	SecondX int
	ThirdX  int
	Color   string
}

var (
	templateMap = make(map[string]baseTemplateData)
)

func main() {
	fmt.Println(time.Now().String())

	templateMap["count"] = baseTemplateData{
		Color:   "#0cccff",
		Width:   125,
		FirstX:  75,
		SecondX: 375,
		ThirdX:  1000,
		Title:   "POC Count",
	}
	templateMap["cves"] = baseTemplateData{
		Color:   "#0cccff",
		Width:   150,
		FirstX:  90,
		SecondX: 450,
		ThirdX:  1200,
		Title:   "CVEs with POC",
	}
	templateMap["exclusive"] = baseTemplateData{
		Color:   "#ffcc33",
		Width:   150,
		FirstX:  90,
		SecondX: 450,
		ThirdX:  1200,
		Title:   "Exclusive POCs",
	}

	knownValidatedSources := providers.ComputeValidatedSources()
	directories := utils.GetDirectories()

	var wg sync.WaitGroup
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
	urlsFromProvider := make(map[string][]string)
	for r := range results {
		if _, ok := aggStats[r.FileJob.Folder]; !ok {
			aggStats[r.FileJob.Folder] = &stats.Stats{Year: r.FileJob.Folder}
			aggStats[r.FileJob.Folder].DomainMap = make(map[string]int)
			aggStats[r.FileJob.Folder].URLMap = make(map[string]int)
			aggStats[r.FileJob.Folder].ProviderMap = make(map[string]*stats.ProviderDetails)
		}
		cveStats := stats.CVEStat{CveID: r.FileJob.CVE, ExploitCount: len(r.Result.Openpoc)}
		aggStats[r.FileJob.Folder].CVECount += 1
		aggStats[r.FileJob.Folder].ExploitCount += cveStats.ExploitCount
		aggStats[r.FileJob.Folder].CveScoreBoard = append(aggStats[r.FileJob.Folder].CveScoreBoard, cveStats)

		knownProviders := []struct {
			provider interface{}
			result   []*types.OpenPocMetadata
		}{
			{public.InTheWild{}, toMetadata(r.Result.InTheWild)},
			{public.Nuclei{}, toMetadata(r.Result.Nuclei)},
			{public.Nomisec{}, toMetadata(r.Result.Nomisec)},
			{public.Trickest{}, toMetadata(r.Result.Trickest)},
			{public.ExploitDB{}, toMetadata(r.Result.ExploitDB)},
			{public.Metasploit{}, toMetadata(r.Result.Metasploit)},
		}

		// Compute the total number of exploits
		for _, providerData := range knownProviders {
			providerName := getProviderName(providerData.provider)
			if _, ok := aggStats[r.FileJob.Folder].ProviderMap[providerName]; !ok {
				aggStats[r.FileJob.Folder].ProviderMap[providerName] = &stats.ProviderDetails{Count: 0, CVE: 0, Exclusive: 0}
			}
			count := len(providerData.result)
			aggStats[r.FileJob.Folder].ProviderMap[providerName].Count += count
			if count > 0 {
				aggStats[r.FileJob.Folder].ProviderMap[providerName].CVE += 1
			}

			// Track which provider returned which URL
			for _, d := range providerData.result {
				dataURL := (*d).GetURL()
				if _, found := urlsFromProvider[dataURL]; !found {
					urlsFromProvider[dataURL] = make([]string, 0)
				}
				urlsFromProvider[dataURL] = append(urlsFromProvider[dataURL], providerName)
			}
		}

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

			if _, ok := aggStats[r.FileJob.Folder].URLMap[poc.URL]; !ok {
				aggStats[r.FileJob.Folder].URLMap[poc.URL] = 0
			}
			aggStats[r.FileJob.Folder].URLMap[poc.URL] += 1
		}
	}

	domainCollector := make(map[string]*stats.DomainCount)
	urlCollector := make(map[string]*stats.URLCount)
	for _, stat := range aggStats {
		// Compute Frequencies
		if stat.CVECount > 0 {
			stat.ExploitCountAverage = float64(stat.ExploitCount) / float64(stat.CVECount)
		}
		// Compute CveScoreBoard
		sort.Slice(stat.CveScoreBoard, func(i, j int) bool {
			// More recent first
			if stat.CveScoreBoard[i].ExploitCount == stat.CveScoreBoard[j].ExploitCount {
				// It's always the same year
				_, ridA := utils.GetCvePartsAsInt(stat.CveScoreBoard[i].CveID)
				_, ridB := utils.GetCvePartsAsInt(stat.CveScoreBoard[j].CveID)
				return ridA > ridB
			}
			return stat.CveScoreBoard[i].ExploitCount > stat.CveScoreBoard[j].ExploitCount
		})
		if len(stat.CveScoreBoard) > scoreboardTop {
			stat.CveScoreBoard = stat.CveScoreBoard[:scoreboardTop]
		}
		// Compute Top Domains
		var dCount []stats.DomainCount
		for domain, count := range stat.DomainMap {
			found := false
			for _, knownValidatedSource := range knownValidatedSources {
				if knownValidatedSource == domain {
					found = true
					break
				}
			}
			if found {
				continue
			}
			dCount = append(dCount, stats.DomainCount{Domain: domain, Count: count})
		}
		sort.Slice(dCount, func(i, j int) bool {
			if dCount[i].Count == dCount[j].Count {
				return dCount[i].Domain > dCount[j].Domain
			}
			return dCount[i].Count > dCount[j].Count
		})
		if len(dCount) > domainTop {
			dCount = dCount[:domainTop]
		}
		stat.DomainScoreBoard = dCount

		// Compute Top URLs
		var uCount []stats.URLCount
		for pocURL, count := range stat.URLMap {
			uCount = append(uCount, stats.URLCount{URL: pocURL, Count: count})
		}
		sort.Slice(uCount, func(i, j int) bool {
			if uCount[i].Count == uCount[j].Count {
				return uCount[i].URL > uCount[j].URL
			}
			return uCount[i].Count > uCount[j].Count
		})
		if len(uCount) > urlTop {
			uCount = uCount[:urlTop]
		}
		stat.URLScoreBoard = uCount

		// Global collectors
		for _, domainCount := range stat.DomainScoreBoard {
			if _, found := domainCollector[domainCount.Domain]; !found {
				domainCollector[domainCount.Domain] = &stats.DomainCount{Domain: domainCount.Domain, Count: domainCount.Count}
			} else {
				domainCollector[domainCount.Domain].Count += domainCount.Count
			}
		}
		for _, urlCount := range stat.URLScoreBoard {
			if _, found := urlCollector[urlCount.URL]; !found {
				urlCollector[urlCount.URL] = &stats.URLCount{URL: urlCount.URL, Count: urlCount.Count}
			} else {
				urlCollector[urlCount.URL].Count += urlCount.Count
			}
		}
		for _, urlFromProvider := range urlsFromProvider {
			// If a provider returned the same URL multiple times, we only count as once
			providersThatGotIt := make(map[string]struct{})
			for _, provider := range urlFromProvider {
				providersThatGotIt[provider] = struct{}{}
			}
			// Update scoring
			for provider := range providersThatGotIt {
				if _, ok := stat.ProviderMap[provider]; !ok {
					stat.ProviderMap[provider] = &stats.ProviderDetails{Count: 0, CVE: 0, Exclusive: 0}
				}
				stat.ProviderMap[provider].Exclusive += 1
			}
		}
	}

	var dCounts []stats.DomainCount
	for _, domainCount := range domainCollector {
		dCounts = append(dCounts, *domainCount)
	}
	sort.Slice(dCounts, func(i, j int) bool {
		return dCounts[i].Count > dCounts[j].Count
	})

	var uCounts []stats.URLCount
	for _, urlCount := range urlCollector {
		uCounts = append(uCounts, *urlCount)
	}
	sort.Slice(uCounts, func(i, j int) bool {
		return uCounts[i].Count > uCounts[j].Count
	})

	OutputAsString(aggStats, dCounts, uCounts)
	OutputTemplateFile(aggStats)

	fmt.Println(time.Now().String())
}

func OutputTemplateFile(aggStats map[string]*stats.Stats) {
	templateFileName := "stats/stats_example.svg"
	statExampleTemplate, err := template.ParseFiles(templateFileName)
	if err != nil {
		fmt.Printf("Could not open template file %s: %v\n", templateFileName, err)
		return
	}

	providerStatsExampleTemplate, err := template.New("svg").Parse(baseTemplate)
	if err != nil {
		fmt.Printf("Could not parse base template: %v\n", err)
		return
	}

	finalStat := stats.Stats{
		ProviderMap: make(map[string]*stats.ProviderDetails),
	}
	for year, stat := range aggStats {
		yearlyOutputFileName := fmt.Sprintf("%s.svg", year)
		yearlyOutputFile, err := os.Create(".github/images/" + yearlyOutputFileName)
		if err != nil {
			fmt.Printf("Could not open output file %s: %v\n", yearlyOutputFileName, err)
			break
		}
		err = statExampleTemplate.Execute(yearlyOutputFile, stat)
		if err != nil {
			fmt.Printf("Could not open run template on file %s: %v\n", yearlyOutputFileName, err)
		}
		yearlyOutputFile.Close()

		for k, v := range stat.ProviderMap {
			if _, ok := finalStat.ProviderMap[k]; !ok {
				finalStat.ProviderMap[k] = v
			} else {
				finalStat.ProviderMap[k].Count += v.Count
				finalStat.ProviderMap[k].CVE += v.CVE
			}
		}
	}

	for providerName, providerData := range finalStat.ProviderMap {
		// Create provider folder
		providerOutputFolder := fmt.Sprintf(".github/images/%s/", providerName)
		if _, err = os.Stat(providerOutputFolder); os.IsNotExist(err) {
			err = os.Mkdir(providerOutputFolder, 0755)
			if err != nil {
				fmt.Printf("Could not create output folder %s: %v\n", providerOutputFolder, err)
				continue
			}
		}

		for statType, templateData := range templateMap {
			providerCountOutputFileName := fmt.Sprintf("%s/%s.svg", providerOutputFolder, statType)
			providerCountOutputFile, err := os.Create(providerCountOutputFileName)
			if err != nil {
				fmt.Printf("Could not open output file %s: %v\n", providerCountOutputFileName, err)
				break
			}
			switch statType {
			case "count":
				templateData.Value = strconv.Itoa(providerData.Count)
			case "cves":
				templateData.Value = strconv.Itoa(providerData.CVE)
			case "exclusive":
				templateData.Value = strconv.Itoa(providerData.Exclusive)
			}
			err = providerStatsExampleTemplate.Execute(providerCountOutputFile, templateData)
			if err != nil {
				fmt.Printf("Could not open run template on file %s: %v\n", providerCountOutputFileName, err)
			}
			providerCountOutputFile.Close()
		}
	}
}

func OutputAsString(aggStats map[string]*stats.Stats, dCounts []stats.DomainCount, uCounts []stats.URLCount) {
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
		fmt.Println("Top CVEs with the most exploits:")
		for i := 0; i < scoreboardTop && i < len(stat.CveScoreBoard); i++ {
			entry := stat.CveScoreBoard[i]
			fmt.Printf("%d. CVE: %s, Exploit Count: %d\n", i+1, entry.CveID, entry.ExploitCount)
		}
		fmt.Println("Top domains with the most exploits:")
		for i := 0; i < domainTop && i < len(stat.DomainScoreBoard); i++ {
			entry := stat.DomainScoreBoard[i]
			fmt.Printf("%d. Domain: %s, Count: %d\n", i+1, entry.Domain, entry.Count)
		}
		fmt.Println("Top URLs with the most exploits:")
		for i := 0; i < urlTop && i < len(stat.URLScoreBoard); i++ {
			entry := stat.URLScoreBoard[i]
			fmt.Printf("%d. URL: %s, Count: %d\n", i+1, entry.URL, entry.Count)
		}
		fmt.Println()
		fmt.Println("Scores per provider:")
		for provider, providerScore := range stat.ProviderMap {
			fmt.Printf("%s. Total: %d, CVE: %d\n", provider, providerScore.Count, providerScore.CVE)
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("Top domains with the most exploits:")
	for i := 0; i < domainTop && i < len(dCounts); i++ {
		entry := dCounts[i]
		fmt.Printf("%d. Domain: %s, Count: %d\n", i+1, entry.Domain, entry.Count)
	}
	fmt.Println()
	fmt.Println("Top URLs with the most exploits:")
	for i := 0; i < urlTop && i < len(uCounts); i++ {
		entry := uCounts[i]
		fmt.Printf("%d. URL: %s, Count: %d\n", i+1, entry.URL, entry.Count)
	}
	fmt.Println()
}

func toMetadata[T types.OpenPocMetadata](input []T) (output []*types.OpenPocMetadata) {
	for _, v := range input {
		metadata := any(v).(types.OpenPocMetadata)
		output = append(output, &metadata)
	}
	return
}

func getProviderName(obj any) string {
	return reflect.TypeOf(obj).Name()
}
