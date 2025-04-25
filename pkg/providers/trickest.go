package providers

import (
	"bufio"
	"errors"
	"openpoc/pkg/types"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

func IsTrickestExploit(candidateFilePath string) bool {
	return filepath.Ext(candidateFilePath) == ".md" && strings.Contains(filepath.Base(candidateFilePath), "CVE-")
}

func ParseTrickest(markdownFilePath string) ([]*types.Trickest, error) {
	fileName := filepath.Base(markdownFilePath)
	cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	file, err := os.ReadFile(markdownFilePath)
	if err != nil {
		return nil, err
	}
	pocURLs := extractTrickestCVEPoCLinks(string(file))

	var records []*types.Trickest
	for _, url := range pocURLs {
		found := false
		trusted := false

		// These are big CVEs databases
		// They may contain dead links, todos (false positives), etc.
		// In practice, we should directly scrap them (but too much data is too much)
		for _, dbURL := range knownValidatedSources {
			if dbURL == url {
				found = true
				trusted = true
				break
			}
		}

		// Common Repository (already index, but trickest often has a few
		// more than even exploit-db did not properly indexed)
		if !found && strings.HasPrefix(url, "www.exploit-db.com") {
			url = strings.TrimSuffix(url, "/")
			found = true
			trusted = true
		}

		// Common Repository (Nomisec indexes GitHub, not gist)
		if !found && strings.Contains(url, "gist.github.com") {
			found = true
		}

		// OK, but we will never trust these
		if !found && strings.Contains(url, "docs.google.com") {
			found = true
		}

		// Find CVE in the name
		// (most links are dead or renamed, so we don't trust them)
		if !found && strings.Contains(url, "CVE-") {
			found = cveRegex.MatchString(url)
			if found {
				cveID = cveRegex.FindString(url)
			}
		}

		if !found {
			for _, dbURL := range knownValidatedButNotTrustedSources {
				if dbURL == url {
					found = true
					break
				}
			}
		}

		// I have chosen to trust this source, even if it's archived
		if url == "github.com/ARPSyndicate/kenzer-templates" {
			trusted = true
		}

		if found {
			records = append(records, &types.Trickest{
				CveID:       cleanTrickestCve(cveID),
				URL:         "https://" + url,
				AddedAt:     types.DefaultDate,
				Trustworthy: trusted,
			})
		}
	}

	return records, nil
}

func ParseTrickestReferences(textFilePath string) (exploits []*types.Trickest, err error) {
	var file *os.File
	file, err = os.Open(textFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			err = errors.New("invalid trickest reference")
			return
		}
		url := cleanTrickestURL(parts[1])
		if url == "" {
			continue
		}
		exploits = append(exploits, &types.Trickest{
			CveID:       cleanTrickestCve(parts[0]),
			URL:         url,
			AddedAt:     types.DefaultDate,
			Trustworthy: false,
		})
	}

	if err = scanner.Err(); err != nil {
		return
	}
	return
}

func cleanTrickestURL(url string) string {
	url = strings.Replace(url, "http://", "https://", -1)
	for _, banned := range knownForbiddenSourcesPrefix {
		if strings.HasPrefix(url, banned) {
			return ""
		}
	}
	// No advisory identifier in the URL
	if url == "https://cert.vde.com/en-us/advisories/" {
		return ""
	}
	return url
}

func extractTrickestCVEPoCLinks(input string) (pocURLs []string) {
	lines := strings.Split(input, "\n")
	canScrap := false
	for _, line := range lines {
		if !canScrap && strings.HasPrefix(line, "### POC") {
			canScrap = true
		}
		if line == "" || line[0] != '-' {
			continue
		}
		line = strings.Split(strings.TrimSpace(line[1:]), " ")[0]
		if line == "" || !strings.HasPrefix(line, "http") {
			continue
		}
		if strings.HasPrefix(line, "https://") {
			line = line[8:]
		} else {
			line = line[7:]
		}
		// At this point, the output looks like a link
		pocURLs = append(pocURLs, line)
	}
	return
}

func cleanTrickestCve(cve string) string {
	if cve == "CVE-7600-2018" {
		cve = "CVE-2018-7600"
	}
	if cve == "CVE-2121-44228" {
		cve = "CVE-2021-44228"
	}
	return utils.CleanCVE(cve)
}

var knownValidatedSources = []string{
	// More than 2k stars
	"github.com/qazbnm456/awesome-cve-poc",
	"github.com/tunz/js-vuln-db",
	"github.com/xairy/linux-kernel-exploitation",
	"github.com/Threekiii/Awesome-POC",
	"github.com/Mr-xn/Penetration_Testing_POC",

	// Less than 1k stars
	"github.com/ycdxsb/WindowsPrivilegeEscalation",
	"github.com/GhostTroops/TOP",
	"github.com/eeeeeeeeee-code/POC",
	"github.com/adysec/POC",
	"github.com/jiayy/android_vuln_poc-exp",
	"github.com/nu11secur1ty/Windows10Exploits",
	"github.com/Al1ex/LinuxEelvation",

	// Less than 200 stars
	"github.com/tzwlhack/Vulnerability",
	"github.com/NyxAzrael/Goby_POC",
	"github.com/ARPSyndicate/kenzer-templates",
	"github.com/DMW11525708/wiki",
	"github.com/JlSakuya/Linux-Privilege-Escalation-Exploits",

	// Not very good, but still valid
	"github.com/n0-traces/cve_monitor",
	"github.com/jev770/badmoodle-scan",
	"github.com/TinyNiko/android_bulletin_notes",
	"github.com/WindowsExploits/Exploits",

	// Closed source
	"seclists.org/",
	"wpscan.com/", "wpvulndb.com/", // new vs old
	"packetstorm.news/", "packetstormsecurity.com/", "packetstormsecurity.org/", // new vs old
	"snyk.io/",
	"talosintelligence.com/",
	"huntr.dev/",
	"hackerone.com/",
	"www.tenable.com/",
	"marc.info/",
	"www.mend.io/vulnerability-database/",
	"www.whitesourcesoftware.com/",
	"www.vulnerability-lab.com/",
	"www.openwall.com/",
}

// Blogs or...
var knownValidatedButNotTrustedSources = []string{
	"codevigilant.com/",
	"pierrekim.github.io/",
	"blog.securityevaluators.com/",
	"medium.com/",
}

// We don't want to know if there is an exploit
// We want a proof that there is at least one public exploit
var knownForbiddenSourcesPrefix = []string{
	"https://vuldb.com/",                                          // vuln details
	"https://security.samsungmobile.com/",                         // vuln details
	"https://www.oracle.com/",                                     // vuln details
	"https://kb.netgear.com/",                                     // vuln details
	"https://usn.ubuntu.com/",                                     // vuln details
	"https://www.ubuntu.com/usn/",                                 // vuln details
	"https://www.qualcomm.com/company/product-security/bulletins", // vuln details
	"https://www.bentley.com/en/common-vulnerability-exposure/",   // vuln details
	"https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html", // dead
	"https://www.foxit.com/support/security-bulletins.html",                           // junk
	"https://www.foxitsoftware.com/support/security-bulletins.php",                    // junk
	"https://www.dlink.com/en/security-bulletin/",                                     // junk
	"https://www.syss.de/pentest-blog/",                                               // this specific endpoint
	"https://kc.mcafee.com/corporate/",                                                // dead
	"https://tools.cisco.com/security/center/content/",                                // vuln details
	"https://www.ibm.com/",                                                            // vuln details
	"https://www.forescout.com/",                                                      // vuln details + "nessus"
	"https://www.kb.cert.org/",                                                        // vuln details
	"https://www.autodesk.com/trust/security-advisories/",                             // vuln details
	"https://devolutions.net/security/advisories/",                                    // vuln details
	"https://nvidia.custhelp.com/app/answers/detail/a_id/",                            // vuln details
	"https://cert.vde.com/en-us/advisories/vde-",                                      // vuln details
	"https://www.coresecurity.com/?action=item",                                       // this specific endpoint
	"https://support.hpe.com/hpsc/doc/public/",                                        // vuln details
	"https://www.securityfocus.com/",                                                  // dead
}
