package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"openpoc/pkg/providers"
	"openpoc/pkg/types"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	isTesting       = true
	indexLimit      = 10
	disableTrickest = true
)

var (
	exploitDB = types.Target{
		URL:       "https://gitlab.com/exploit-database/exploitdb.git",
		Folder:    "datasources/exploitdb",
		Branch:    "main",
		Completed: isTesting,
		Range:     24,
	}
	exploitDBFilename = "files_exploits.csv"

	inTheWild = types.Target{
		URL:       "https://inthewild.io/api/exploits",
		Folder:    "datasources/inthewild",
		Branch:    "",
		Completed: isTesting,
		Range:     48,
	}
	inTheWildFilename = "pocs.json"

	trickest = types.Target{
		URL:       "https://github.com/trickest/cve.git",
		Folder:    "datasources/trickest",
		Branch:    "main",
		Completed: isTesting,
		Range:     24,
	}
	trickestFilename = "references.txt"
)

func main() {
	fmt.Println(time.Now().String())

	var err error
	yearMap := make(map[string]map[string]*types.AggregatorResult)

	//
	// ExploitDB
	//
	var newExploitDB []*types.ExploitDB
	exploitDBFile := filepath.Join(exploitDB.Folder, exploitDBFilename)
	exploitDB.Completed = utils.WasModifiedWithin(exploitDBFile, exploitDB.Range)

	if !exploitDB.Completed {
		fmt.Println("Download ExploitDB Results.")
		// Clone repository (shallow and no checkout)
		if err = utils.GitClone("", exploitDB.URL, exploitDB.Folder, 1, "--no-checkout"); err == nil {
			// We will only plan to clone specific files
			if err = utils.RunCommandDir(exploitDB.Folder, "git", "config", "core.sparseCheckout", "true"); err == nil {
				// We will only fetch the file below
				sparsePath := filepath.Join(exploitDB.Folder, ".git", "info", "sparse-checkout")
				if err = os.WriteFile(sparsePath, []byte(exploitDBFilename+"\n"), 0644); err == nil {
					// We can process with the fetch
					if err = utils.RunCommandDir(exploitDB.Folder, "git", "checkout", exploitDB.Branch); err == nil {
						if newExploitDB, err = providers.ParseExploitDB(exploitDBFile); err == nil {
							exploitDB.Completed = true
						} else {
							fmt.Printf("Error parsing database %s: %v\n", exploitDBFile, err)
						}
					} else {
						fmt.Printf("Error setting sparseCheckout file for exploitdb: %v\n", err)
					}
				} else {
					fmt.Printf("Error setting sparseCheckout file for exploitdb: %v\n", err)
				}
			} else {
				fmt.Printf("Error setting sparseCheckout for exploitdb: %v\n", err)
			}
		} else {
			fmt.Printf("Error cloning %s: %v\n", exploitDB.URL, err)
		}
	} else {
		fmt.Println("Process ExploitDB Results.")
		if newExploitDB, err = providers.ParseExploitDB(exploitDBFile); err != nil {
			fmt.Printf("Error parsing exploitdb database %s: %v\n", exploitDBFile, err)
		}
	}

	//
	// InTheWild
	//
	var newInTheWild []*types.InTheWild
	inTheWildFile := filepath.Join(inTheWild.Folder, inTheWildFilename)
	inTheWild.Completed = utils.WasModifiedWithin(inTheWildFile, inTheWild.Range)

	if !inTheWild.Completed {
		fmt.Println("Download InTheWild Results.")
		var response *http.Response
		var outFile *os.File
		// Create the folder to store the file
		if err = os.MkdirAll(inTheWild.Folder, 0755); err == nil {
			// Fetch the data from the API
			if response, err = http.Get(inTheWild.URL); err == nil {
				defer response.Body.Close()
				// Ensure the response was successful
				if response.StatusCode == http.StatusOK {
					// Store the response
					outFile, err = os.Create(inTheWildFile)
					if err == nil {
						if _, err = io.Copy(outFile, response.Body); err == nil {
							if newInTheWild, err = providers.ParseInTheWild(inTheWildFile); err == nil {
								inTheWild.Completed = true
							} else {
								fmt.Printf("Error parsing database %s: %v\n", inTheWildFile, err)
							}
						} else {
							fmt.Printf("Error storing response in file %s: %v\n", inTheWildFile, err)
						}
						outFile.Close()
					} else {
						fmt.Printf("Error creating file: %v\n", err)
					}
				} else {
					fmt.Printf("Unexpected status code for in the wild: %d", response.StatusCode)
				}
			} else {
				fmt.Printf("Could not fetch %s: %v\n", inTheWild.URL, err)
			}
		} else {
			fmt.Printf("Error creating in the wild folder: %v\n", err)
		}
	} else {
		fmt.Println("Process InTheWild Results.")
		if newInTheWild, err = providers.ParseInTheWild(inTheWildFile); err != nil {
			fmt.Printf("Error parsing database %s: %v\n", inTheWildFile, err)
		}
	}

	//
	// Trickest
	//
	var newTrickest []*types.Trickest
	trickestFile := filepath.Join(trickest.Folder, trickestFilename)
	trickest.Completed = utils.WasModifiedWithin(trickestFile, trickest.Range)
	trickestWorker := func(path string) error {
		if !providers.IsTrickestExploit(path) {
			return nil
		}
		var results []*types.Trickest
		results, err = providers.ParseTrickest(path)
		if err != nil {
			return err
		}
		for _, result := range results {
			newTrickest = append(newTrickest, result)
		}
		return nil
	}

	if !trickest.Completed {
		fmt.Println("Download Trickest Results.")
		// Clone repository (shallow and no checkout)
		if err = utils.GitClone("", trickest.URL, trickest.Folder, 0); err == nil {
			trickest.Completed = true
		} else {
			fmt.Printf("Error cloning %s: %v\n", trickest.URL, err)
		}
	}

	if trickest.Completed && !disableTrickest {
		fmt.Println("Process Trickest Results.")
		// Parses And Add To Trickest Each Markdown
		if err = utils.ProcessFiles(trickest.Folder, trickestWorker); err == nil {
			// Add references
			var referencesTrickest []*types.Trickest
			if referencesTrickest, err = providers.ParseTrickestReferences(trickestFile); err == nil {
				// References are more trustworthy, but not all CVEs are in "references"
				// And we don't have a "date" for references
				for _, candidate := range newTrickest {
					var found bool
					for _, ref := range referencesTrickest {
						if candidate.GetURL() == ref.GetURL() {
							found = true
							ref.AddedAt = candidate.AddedAt
							ref.Trustworthy = candidate.Trustworthy
							break
						}
					}
					if !found {
						referencesTrickest = append(referencesTrickest, candidate)
					}
				}
				newTrickest = referencesTrickest
			} else {
				fmt.Printf("Error processing %s: %v\n", trickestFile, err)
			}
		} else {
			fmt.Printf("Error processing %s: %v\n", trickest.URL, err)
		}
	}

	//
	// Add to the map
	//
	fmt.Println("Prepare results.")
	for _, exploit := range newExploitDB {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].ExploitDB = append(yearMap[year][jsonFilePath].ExploitDB, *exploit)
		}
	}
	for _, exploit := range newInTheWild {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].InTheWild = append(yearMap[year][jsonFilePath].InTheWild, *exploit)
		}
	}
	for _, exploit := range newTrickest {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].Trickest = append(yearMap[year][jsonFilePath].Trickest, *exploit)
		}
	}

	//
	// Write to Disk
	//
	fmt.Println("Write results to disk.")
	i := 0
	for year, results := range yearMap {
		fmt.Printf("Write results for year [%s] to disk.\n", year)
		err := os.MkdirAll(year, 0755)
		if err != nil {
			fmt.Printf("error creating directory: %v", err)
			return
		}
		for jsonFilePath, result := range results {
			var finalResult *types.AggregatorResult
			file, err := os.OpenFile(jsonFilePath, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				fmt.Printf("error opening JSON file: %v\n", err)
				return
			}
			info, err := file.Stat()
			if err != nil {
				file.Close()
				fmt.Printf("error stating file: %v\n", err)
				return
			}
			if info.Size() > 0 {
				var existingResult types.AggregatorResult
				decoder := json.NewDecoder(file)
				err = decoder.Decode(&existingResult)
				if err != nil {
					file.Close()
					fmt.Printf("error decoding existing JSON file: %v\n", err)
					return
				}
				finalResult = MergeAggregatorResults(result, &existingResult)
			} else {
				finalResult = result
			}

			// Create OpenPoC which is a sort of summary of all sources
			merger := make(map[string]*types.OpenpocProduct)
			for _, exploit := range finalResult.Trickest { // dirty, first
				addToMerger(&exploit, &merger)
			}
			for _, exploit := range finalResult.InTheWild { // not often updated, second
				addToMerger(&exploit, &merger)
			}
			for _, exploit := range finalResult.ExploitDB { // good third
				addToMerger(&exploit, &merger)
			}
			for _, url := range merger {
				finalResult.Openpoc = append(finalResult.Openpoc, *url)
			}
			sort.Slice(finalResult.ExploitDB, func(i, j int) bool {
				return finalResult.ExploitDB[i].GetURL() < finalResult.ExploitDB[j].GetURL()
			})
			sort.Slice(finalResult.InTheWild, func(i, j int) bool {
				return finalResult.InTheWild[i].GetURL() < finalResult.InTheWild[j].GetURL()
			})
			sort.Slice(finalResult.Trickest, func(i, j int) bool {
				return finalResult.Trickest[i].GetURL() < finalResult.Trickest[j].GetURL()
			})
			sort.Slice(finalResult.Openpoc, func(i, j int) bool {
				return finalResult.Openpoc[i].URL < finalResult.Openpoc[j].URL
			})

			err = file.Truncate(0)
			if err != nil {
				file.Close()
				fmt.Printf("error truncating file: %v\n", err)
				return
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				file.Close()
				fmt.Printf("error seeking to file start: %v\n", err)
				return
			}

			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(finalResult)
			file.Close()
			if err != nil {
				fmt.Printf("error writing to JSON file: %v\n", err)
				return
			}

			i++
			if isTesting && i >= indexLimit {
				break
			}
		}
	}
	fmt.Println(time.Now().String())
}

func MergeAggregatorResults(newResult *types.AggregatorResult, oldResult *types.AggregatorResult) *types.AggregatorResult {
	if !exploitDB.Completed {
		newResult.ExploitDB = oldResult.ExploitDB
	}
	if !inTheWild.Completed {
		newResult.InTheWild = oldResult.InTheWild
	}
	if !trickest.Completed {
		newResult.Trickest = oldResult.Trickest
	}
	return newResult
}

func addToYearMap[T types.OpenPocMetadata](exploit T, yearMap *map[string]map[string]*types.AggregatorResult) (string, string) {
	year := utils.GetCVEYear(exploit.GetCve())
	if year == "" {
		fmt.Printf("[WRN] Error parsing: <%s>\n", exploit.GetCve())
		return "", ""
	}
	if _, ok := (*yearMap)[year]; !ok {
		(*yearMap)[year] = make(map[string]*types.AggregatorResult)
	}
	// While there is a regex, we add some protection just in case
	jsonFilePath := filepath.Join(filepath.Base(year), filepath.Base(exploit.GetCve()+".json"))
	if _, ok := (*yearMap)[year][jsonFilePath]; !ok {
		(*yearMap)[year][jsonFilePath] = &types.AggregatorResult{
			InTheWild: []types.InTheWild{},
			ExploitDB: []types.ExploitDB{},
			Trickest:  []types.Trickest{},
			Openpoc:   []types.OpenpocProduct{},
		}
	}
	return year, jsonFilePath
}

func addToMerger[T types.OpenPocMetadata](exploit T, merger *map[string]*types.OpenpocProduct) {
	value, found := (*merger)[exploit.GetURL()]
	if !found {
		(*merger)[exploit.GetURL()] = &types.OpenpocProduct{
			Cve:         exploit.GetCve(),
			URL:         exploit.GetURL(),
			AddedAt:     exploit.GetPublishDate(),
			Trustworthy: exploit.IsTrustworthy(),
		}
	} else if !value.Trustworthy {
		value.Trustworthy = exploit.IsTrustworthy()
	}
}
