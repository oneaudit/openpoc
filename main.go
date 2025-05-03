package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"openpoc/pkg/providers"
	"openpoc/pkg/types"
	providertypes "openpoc/pkg/types/public"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"time"
)

const (
	isTesting              = false
	statusByDefault        = false
	indexLimit             = 10
	onlyYear               = ""
	disableExploitDB       = false
	disableInTheWild       = false
	disableTrickest        = false
	disableNomisec         = false
	disableNucleiTemplates = false
	disableMetasploit      = false
)

var disableHolloways = os.Getenv("CAN_ACCESS_HOLLOWAYS") == ""

const (
	version         = "0.8.1"
	versionFilename = ".version"
)

var (
	exploitDB = types.Target{
		URL:       "https://gitlab.com/exploit-database/exploitdb.git",
		Folder:    "datasources/exploitdb",
		Branch:    "main",
		Completed: statusByDefault,
		Range:     24,
	}
	exploitDBFilename = "files_exploits.csv"

	inTheWild = types.Target{
		URL:       "https://inthewild.io/api/exploits",
		Folder:    "datasources/inthewild",
		Branch:    "",
		Completed: statusByDefault,
		Range:     24 * 7,
	}
	inTheWildFilename = "pocs.json"

	trickest = types.Target{
		URL:       "https://github.com/trickest/cve.git",
		Folder:    "datasources/trickest",
		Branch:    "main",
		Completed: statusByDefault,
		Range:     24,
	}
	trickestFilename      = "references.txt"
	trickestCacheFilename = "datasources/trickest.cache"

	nomisec = types.Target{
		URL:       "https://github.com/nomi-sec/PoC-in-GitHub.git",
		Folder:    "datasources/nomisec",
		Branch:    "master",
		Completed: statusByDefault,
		Range:     24,
	}
	nomisecFilename = "README.md"

	nucleiTemplates = types.Target{
		URL:       "https://github.com/projectdiscovery/nuclei-templates.git",
		Folder:    "datasources/nuclei-templates",
		Branch:    "main",
		Completed: statusByDefault,
		Range:     24,
	}
	nucleiTemplatesFilename = ".new-additions"
	nucleiCacheFilename     = "datasources/nuclei.cache"

	metasploit = types.Target{
		URL:       "https://github.com/rapid7/metasploit-framework.git",
		Folder:    "datasources/metasploit",
		Branch:    "master",
		Completed: statusByDefault,
		Range:     6,
	}
	metasploitFilename      = "db/modules_metadata_base.json"
	metasploitCacheFilename = "datasources/metasploit.cache"

	// Holloways' code is private, but results from openpoc are public
	holloways = types.Target{
		URL:       "https://github.com/oneaudit/trickest-extended.git",
		Folder:    "datasources/holloways",
		Branch:    "update",
		Completed: statusByDefault,
		Range:     24,
	}
	hollowaysFilename = "results/database.json"
)

func main() {
	fmt.Println(time.Now().String())

	// Changes to the format means we need to recompile every file
	if _, err := os.Stat(versionFilename); err == nil || !os.IsNotExist(err) {
		var data []byte
		data, err = os.ReadFile(versionFilename)
		if err != nil {
			fmt.Printf("Error reading version file: %v\n", err)
			return
		}

		storedVersion := string(data)
		if storedVersion == version {
			fmt.Println("Version matches:", storedVersion)
		} else {
			fmt.Printf("Version mismatch! Stored: %s, Current: %s\n", storedVersion, version)
			folders := utils.GetDirectories()
			for _, folder := range folders {
				err = os.RemoveAll(folder)
				if err != nil {
					fmt.Printf("Error removing folder %s: %v\n", folder, err)
					return
				}
			}
			fmt.Println("All folders were removed.")
		}
	} else if err != nil {
		fmt.Printf("Error reading version file: %v\n", err)
	}

	if err := os.WriteFile(versionFilename, []byte(version), 0644); err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	} else {
		fmt.Printf("File created with version: %s\n", version)
	}

	var err error
	yearMap := make(map[string]map[string]*types.AggregatorResult)

	//
	// ExploitDB
	//
	var newExploitDB []*providertypes.ExploitDB
	exploitDBFile := filepath.Join(exploitDB.Folder, exploitDBFilename)
	exploitDB.Completed = utils.WasModifiedWithin(exploitDBFile, exploitDB.Range) || exploitDB.Completed

	if !exploitDB.Completed {
		fmt.Println("Download ExploitDB CSV.")
		// Clone repository (shallow and no checkout)
		if err = utils.GitClone("", exploitDB.URL, exploitDB.Folder, 1, "", "--no-checkout"); err == nil {
			// We will only plan to clone specific files
			if err = utils.RunCommandDir(exploitDB.Folder, "git", "config", "core.sparseCheckout", "true"); err == nil {
				// We will only fetch the file below
				sparsePath := filepath.Join(exploitDB.Folder, ".git", "info", "sparse-checkout")
				if err = os.WriteFile(sparsePath, []byte(exploitDBFilename+"\n"), 0644); err == nil {
					// We can process with the fetch
					if err = utils.RunCommandDir(exploitDB.Folder, "git", "checkout", exploitDB.Branch); err == nil {
						exploitDB.Completed = true
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
	}

	if exploitDB.Completed && !disableExploitDB {
		fmt.Println("Process ExploitDB Results.")
		if newExploitDB, err = providers.ParseExploitDB(exploitDBFile); err != nil {
			fmt.Printf("Error parsing exploitdb database %s: %v\n", exploitDBFile, err)
		}
	} else {
		fmt.Println("Skip ExploitDB Results.")
	}

	//
	// Holloways
	//
	var newHolloways []*providertypes.Holloways
	if !disableHolloways {
		hollowaysFile := filepath.Join(holloways.Folder, hollowaysFilename)
		holloways.Completed = utils.WasModifiedWithin(hollowaysFile, holloways.Range) || holloways.Completed

		if !holloways.Completed {
			fmt.Println("Download Holloways JSON.")
			// Clone repository (shallow)
			if err = utils.GitClone("", holloways.URL, holloways.Folder, 1, holloways.Branch); err == nil {
				holloways.Completed = true
			} else {
				fmt.Printf("Error cloning %s: %v\n", holloways.URL, err)
			}
		}

		if holloways.Completed {
			fmt.Println("Process Holloways Results.")
			if newHolloways, err = providers.ParseHolloways(hollowaysFile); err != nil {
				fmt.Printf("Error parsing holloways database %s: %v\n", hollowaysFile, err)
			}
		}
	} else {
		fmt.Println("Holloways is not enabled.")
	}

	//
	// InTheWild
	//
	var newInTheWild []*providertypes.InTheWild
	inTheWildFile := filepath.Join(inTheWild.Folder, inTheWildFilename)
	inTheWild.Completed = utils.WasModifiedWithin(inTheWildFile, inTheWild.Range) || inTheWild.Completed

	if !inTheWild.Completed {
		fmt.Println("Download InTheWild JSON.")
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
							inTheWild.Completed = true
						} else {
							fmt.Printf("Error storing response in file %s: %v\n", inTheWildFile, err)
						}
						err = outFile.Close()
						if err != nil {
							fmt.Printf("could not close file: %v\n", err)
						}
					} else {
						fmt.Printf("Error creating file: %v\n", err)
					}
				} else {
					fmt.Printf("Unexpected status code for in the wild: %d\n", response.StatusCode)
				}
			} else {
				fmt.Printf("Could not fetch %s: %v\n", inTheWild.URL, err)
			}
		} else {
			fmt.Printf("Error creating in the wild folder: %v\n", err)
		}
	}

	if inTheWild.Completed && !disableInTheWild {
		fmt.Println("Process InTheWild Results.")
		if newInTheWild, err = providers.ParseInTheWild(inTheWildFile); err != nil {
			fmt.Printf("Error parsing database %s: %v\n", inTheWildFile, err)
		}
	} else {
		fmt.Println("Skip InTheWild Results.")
	}

	//
	// Trickest
	//
	var newTrickest []*providertypes.Trickest
	trickestDatesCache := utils.LoadCache(trickestCacheFilename)
	trickestFile := filepath.Join(trickest.Folder, trickestFilename)
	trickest.Completed = utils.WasModifiedWithin(trickestFile, trickest.Range) || trickest.Completed
	trickestWorker := func(fileInfo types.FileJob) ([]*providertypes.Trickest, error) {
		if !providers.IsTrickestExploit(fileInfo.Path) {
			return nil, nil
		}
		return providers.ParseTrickest(fileInfo.Folder, fileInfo.Path, trickestDatesCache)
	}

	if !trickest.Completed {
		fmt.Println("Download Trickest.")
		// Clone repository (shallow and no checkout)
		if err = utils.GitClone("", trickest.URL, trickest.Folder, 0, trickest.Branch); err == nil {
			trickest.Completed = true
		} else {
			fmt.Printf("Error cloning %s: %v\n", trickest.URL, err)
		}
	}
	if trickest.Completed && !disableTrickest {
		fmt.Println("Process Trickest Results.")
		// Parses And Add To Trickest Each Markdown
		if newTrickest, err = utils.ProcessFiles(trickest.Folder, 50, trickestWorker); err == nil {
			// Add references
			var referencesTrickest []*providertypes.Trickest
			if referencesTrickest, err = providers.ParseTrickestReferences(trickestFile); err == nil {
				// References are more trustworthy, but not all CVEs are in "references"
				// And we don't have a "date" for references
				var finalTrickest []*providertypes.Trickest
				known := make(map[string]map[string]*providertypes.Trickest)
				for _, candidate := range newTrickest {
					if _, found := known[candidate.CveID]; !found {
						known[candidate.CveID] = make(map[string]*providertypes.Trickest)
					}
					if _, found := known[candidate.CveID][candidate.URL]; !found {
						known[candidate.CveID][candidate.URL] = candidate
					} else {
						// we could assert it, but the candidate are exactly the same
					}
				}
				for _, candidate := range referencesTrickest {
					if _, found := known[candidate.CveID]; !found {
						known[candidate.CveID] = make(map[string]*providertypes.Trickest)
					}
					if _, found := known[candidate.CveID][candidate.URL]; !found {
						known[candidate.CveID][candidate.URL] = candidate
					} else {
						// we ignore duplicates, as trickest references have less information
					}
				}
				for _, list := range known {
					for _, candidate := range list {
						finalTrickest = append(finalTrickest, candidate)
					}
				}
				newTrickest = finalTrickest
			} else {
				fmt.Printf("Error processing %s: %v\n", trickestFile, err)
			}
		} else {
			fmt.Printf("Error processing %s: %v\n", trickest.URL, err)
		}

		// Save the latest version of the cache
		err = utils.SaveCache(trickestCacheFilename, trickestDatesCache)
		if err != nil {
			fmt.Printf("Error caching %s: %v\n", trickestCacheFilename, err)
		}
	} else {
		fmt.Println("Skip Trickest Results.")
	}

	//
	// Nomisec
	//
	var newNomisec []*providertypes.Nomisec
	nomisecFile := filepath.Join(nomisec.Folder, nomisecFilename)
	nomisec.Completed = utils.WasModifiedWithin(nomisecFile, nomisec.Range) || nomisec.Completed
	nomisecWorker := func(fileInfo types.FileJob) ([]*providertypes.Nomisec, error) {
		if !providers.IsNomisec(fileInfo.Path) {
			return nil, nil
		}
		return providers.ParseNomicsec(fileInfo.Path)
	}

	if !nomisec.Completed {
		fmt.Println("Download NomiSec.")
		// Clone repository (shallow and no checkout)
		if err = utils.GitClone("", nomisec.URL, nomisec.Folder, 1, nomisec.Branch); err == nil {
			nomisec.Completed = true
		} else {
			fmt.Printf("Error cloning %s: %v\n", nomisec.URL, err)
		}
	}

	if nomisec.Completed && !disableNomisec {
		fmt.Println("Process NomiSec Results.")
		// Parses And Adds Each JSON To NomiSec
		if newNomisec, err = utils.ProcessFiles(nomisec.Folder, 8, nomisecWorker); err != nil {
			fmt.Printf("Error processing %s: %v\n", nomisec.URL, err)
		}
	} else {
		fmt.Println("Skip NomiSec Results.")
	}

	//
	// Nuclei Templates
	//
	var newNuclei []*providertypes.Nuclei
	nucleiDatesCache := utils.LoadCache(nucleiCacheFilename)
	nucleiTemplatesFilePath := filepath.Join(nucleiTemplates.Folder, nucleiTemplatesFilename)
	nucleiTemplates.Completed = utils.WasModifiedWithin(nucleiTemplatesFilePath, nucleiTemplates.Range) || nucleiTemplates.Completed
	nucleiTemplatesWorker := func(fileInfo types.FileJob) ([]*providertypes.Nuclei, error) {
		if !providers.IsNucleiTemplate(fileInfo.Path) {
			return nil, nil
		}
		return providers.ParseNucleiTemplate(fileInfo.Folder, fileInfo.Path, nucleiDatesCache)
	}

	if !nucleiTemplates.Completed {
		fmt.Println("Download Nuclei Templates.")
		// Clone repository (shallow and no checkout)
		if err = utils.GitClone("", nucleiTemplates.URL, nucleiTemplates.Folder, 0, nucleiTemplates.Branch); err == nil {
			nucleiTemplates.Completed = true
		} else {
			fmt.Printf("Error cloning %s: %v\n", nucleiTemplates.URL, err)
		}
	}

	if nucleiTemplates.Completed && !disableNucleiTemplates {
		fmt.Println("Process Nuclei Templates Results.")
		// Parses And Adds Each JSON To Nuclei Templates
		if newNuclei, err = utils.ProcessFiles(nucleiTemplates.Folder, 8, nucleiTemplatesWorker); err != nil {
			fmt.Printf("Error processing %s: %v\n", nucleiTemplates.URL, err)
		}

		// Save the latest version of the cache
		err = utils.SaveCache(nucleiCacheFilename, nucleiDatesCache)
		if err != nil {
			fmt.Printf("Error caching %s: %v\n", nucleiCacheFilename, err)
		}
	} else {
		fmt.Println("Skip Nuclei Templates Results.")
	}

	//
	// Metasploit
	//
	var newMetasploit []*providertypes.Metasploit
	metasploitDatesCache := utils.LoadCache(metasploitCacheFilename)
	metasploitTemplatesFilePath := filepath.Join(metasploit.Folder, metasploitFilename)
	metasploit.Completed = utils.WasModifiedWithin(metasploitTemplatesFilePath, metasploit.Range) || metasploit.Completed
	metasploitWorker := func(fileInfo types.FileJob) ([]*providertypes.Metasploit, error) {
		if !providers.IsMetasploit(fileInfo.Path) {
			return nil, nil
		}
		return providers.ParseMetasploit(fileInfo.Folder, fileInfo.Path, metasploitDatesCache)
	}

	if !metasploit.Completed {
		// Clone repository (no checkout)
		if err = utils.GitClone("", metasploit.URL, metasploit.Folder, 0, "", "--no-checkout"); err == nil {
			// We will only plan to clone specific folders
			if err = utils.RunCommandDir(metasploit.Folder, "git", "sparse-checkout", "init", "--cone"); err == nil {
				// We will only plan to clone specific folders
				if err = utils.RunCommandDir(metasploit.Folder, "git", "sparse-checkout", "set", "modules"); err == nil {
					// We can process with the fetch
					if err = utils.RunCommandDir(metasploit.Folder, "git", "checkout", metasploit.Branch); err == nil {
						metasploit.Completed = true
					} else {
						fmt.Printf("Error setting sparseCheckout folder for metasploit: %v\n", err)
					}
				} else {
					fmt.Printf("Error setting sparseCheckout folder for metasploit: %v\n", err)
				}
			} else {
				fmt.Printf("Error setting sparseCheckout for metasploit: %v\n", err)
			}
		} else {
			fmt.Printf("Error cloning %s: %v\n", metasploit.URL, err)
		}
	}

	if metasploit.Completed && !disableMetasploit {
		fmt.Println("Process Metasploit Results.")
		// Parses And Adds Each JSON To Metasploit
		if newMetasploit, err = utils.ProcessFiles(metasploit.Folder, 8, metasploitWorker); err == nil {
			// Save the latest version of the cache
			err = utils.SaveCache(metasploitCacheFilename, metasploitDatesCache)
			if err != nil {
				fmt.Printf("Error caching %s: %v\n", metasploit.Folder, err)
			}
		} else {
			fmt.Printf("Error processing %s: %v\n", metasploit.URL, err)
		}

		// Save the latest version of the cache
		err = utils.SaveCache(metasploitCacheFilename, metasploitDatesCache)
		if err != nil {
			fmt.Printf("Error caching %s: %v\n", metasploitCacheFilename, err)
		}
	} else {
		fmt.Println("Skip Metasploit Results.")
	}

	//
	// Add to the map
	//
	fmt.Println("Prepare results.")
	for _, exploit := range newExploitDB {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].ExploitDB = append(yearMap[year][jsonFilePath].ExploitDB, exploit)
		} else {
			fmt.Printf("[ExploitDB] Skipping %s [%s].\n", exploit.GetCve(), exploit.GetURL())
		}
	}
	for _, exploit := range newInTheWild {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].InTheWild = append(yearMap[year][jsonFilePath].InTheWild, exploit)
		} else {
			fmt.Printf("[InTheWild] Skipping %s [%s].\n", exploit.GetCve(), exploit.GetURL())
		}
	}
	for _, exploit := range newTrickest {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].Trickest = append(yearMap[year][jsonFilePath].Trickest, exploit)
		} else {
			fmt.Printf("[Trickest] Skipping %s [%s].\n", exploit.GetCve(), exploit.GetURL())
		}
	}
	for _, exploit := range newNomisec {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].Nomisec = append(yearMap[year][jsonFilePath].Nomisec, exploit)
		} else {
			fmt.Printf("[Nomisec] Skipping %s [%s].\n", exploit.GetCve(), exploit.GetURL())
		}
	}
	for _, exploit := range newNuclei {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].Nuclei = append(yearMap[year][jsonFilePath].Nuclei, exploit)
		} else {
			fmt.Printf("[Nuclei] Skipping %s [%s].\n", exploit.GetCve(), exploit.GetURL())
		}
	}
	for _, exploit := range newMetasploit {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].Metasploit = append(yearMap[year][jsonFilePath].Metasploit, exploit)
		} else {
			fmt.Printf("[Metasploit] Skipping %s [%s].\n", exploit.GetCve(), exploit.GetURL())
		}
	}
	for _, exploit := range newHolloways {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].Holloways = append(yearMap[year][jsonFilePath].Holloways, exploit)
		} else {
			fmt.Printf("[Holloways] Skipping %s.%s\n", exploit.GetCve(), exploit.GetURL())
		}
	}

	//
	// Write to Disk
	//
	fmt.Println("Write results to disk.")
	i := 0
	for year, results := range yearMap {
		if onlyYear != "" && year != onlyYear {
			continue
		}

		fmt.Printf("Write results for year [%s] to disk.\n", year)
		err := os.MkdirAll(year, 0755)
		if err != nil {
			fmt.Printf("error creating directory %s: %v\n", year, err)
			return
		}
		for jsonFilePath, result := range results {
			var finalResult *types.AggregatorResult
			file, err := os.OpenFile(jsonFilePath, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				fmt.Printf("error opening JSON file %s: %v\n", jsonFilePath, err)
				return
			}
			info, err := file.Stat()
			if err != nil {
				err = file.Close()
				if err != nil {
					fmt.Printf("could not close file %s: %v\n", jsonFilePath, err)
					return
				}
				fmt.Printf("error stating file %s: %v\n", jsonFilePath, err)
				return
			}
			if info.Size() > 0 {
				var existingResult types.AggregatorResult
				decoder := json.NewDecoder(file)
				err = decoder.Decode(&existingResult)
				if err != nil {
					fmt.Printf("error decoding existing JSON file %s: %v\n", jsonFilePath, err)

					// Disregard the JSON file that could not be parsed
					// As it may be due to an update
					finalResult = result
				} else {
					finalResult = MergeAggregatorResults(result, &existingResult)
				}
			} else {
				finalResult = result
			}

			// Create OpenPoC which is a sort of summary of all sources
			finalResult.ComputeOpenPoc()
			finalResult.Sort()

			// If there are no PoCs anymore, delete the file
			if finalResult.IsEmpty() {
				err = file.Close()
				if err != nil {
					fmt.Printf("could not close file %s: %v\n", jsonFilePath, err)
					return
				}
				err = os.Remove(jsonFilePath)
				if err != nil {
					fmt.Printf("could not remove empty file %s: %v\n", jsonFilePath, err)
					return
				}
				continue
			}

			err = file.Truncate(0)
			if err != nil {
				fmt.Printf("error truncating file %s: %v\n", jsonFilePath, err)
				err = file.Close()
				if err != nil {
					fmt.Printf("could not close file %s: %v\n", jsonFilePath, err)
					return
				}
				return
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				err = file.Close()
				if err != nil {
					fmt.Printf("could not close file %s: %v\n", jsonFilePath, err)
					return
				}
				fmt.Printf("error seeking to file start %s: %v\n", jsonFilePath, err)
				return
			}

			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(finalResult)
			if err != nil {
				fmt.Printf("error writing to JSON file %s: %v\n", jsonFilePath, err)
				err = file.Close()
				if err != nil {
					fmt.Printf("could not close file %s: %v\n", jsonFilePath, err)
					return
				}
				return
			}
			err = file.Close()
			if err != nil {
				fmt.Printf("could not close file %s: %v\n", jsonFilePath, err)
				return
			}

			i++
			if isTesting && i >= indexLimit {
				break
			}
		}
		if isTesting && i >= indexLimit {
			break
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
		for i, v := range newResult.InTheWild {
			_, v.Score = providers.InspectAggregatorURL(v.GetURL(), v.GetCve(), false)
			newResult.InTheWild[i] = v
		}
	}
	if !trickest.Completed {
		newResult.Trickest = oldResult.Trickest
		for i, v := range newResult.Trickest {
			_, v.Score = providers.InspectAggregatorURL(v.GetURL(), v.GetCve(), false)
			newResult.Trickest[i] = v
		}
	}
	if !metasploit.Completed {
		newResult.Metasploit = oldResult.Metasploit
	}
	if !nucleiTemplates.Completed {
		newResult.Nuclei = oldResult.Nuclei
	}
	if !nomisec.Completed {
		newResult.Nomisec = oldResult.Nomisec
	}
	if !holloways.Completed {
		newResult.Holloways = oldResult.Holloways
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
		(*yearMap)[year][jsonFilePath] = types.NewAggregatorResult()
	}
	return year, jsonFilePath
}
