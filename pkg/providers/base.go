package providers

import (
	"net/url"
	"strings"
)

var knownValidatedSources = []string{
	// More than 2k stars
	"https://github.com/qazbnm456/awesome-cve-poc",
	"https://github.com/tunz/js-vuln-db",
	"https://github.com/xairy/linux-kernel-exploitation",
	"https://github.com/Threekiii/Awesome-POC",
	"https://github.com/Mr-xn/Penetration_Testing_POC",

	// Less than 1k stars
	"https://github.com/ycdxsb/WindowsPrivilegeEscalation",
	"https://github.com/GhostTroops/TOP",
	"https://github.com/eeeeeeeeee-code/POC",
	"https://github.com/adysec/POC",
	"https://github.com/jiayy/android_vuln_poc-exp",
	"https://github.com/nu11secur1ty/Windows10Exploits",
	"https://github.com/Al1ex/LinuxEelvation",

	// Less than 200 stars
	"https://github.com/tzwlhack/Vulnerability",
	"https://github.com/NyxAzrael/Goby_POC",
	"https://github.com/DMW11525708/wiki",
	"https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits",

	// Not very good, but still valid
	"https://github.com/n0-traces/cve_monitor",
	"https://github.com/jev770/badmoodle-scan",
	"https://github.com/TinyNiko/android_bulletin_notes",
	"https://github.com/WindowsExploits/Exploits",
}

// Must ends with a slash to be a valid prefix
var knownValidatedSourcesPrefix = []string{
	"https://seclists.org/",
	"https://wpscan.com/",
	"https://packetstorm.news/",
	"https://security.snyk.io/", "https://snyk.io/vuln/", // new vs old
	"https://talosintelligence.com/", "https://www.talosintelligence.com/",
	"https://huntr.dev/", "https://huntr.com/",
	"https://hackerone.com/",
	"https://www.tenable.com/",
	"https://www.openwall.com/", "https://openwall.com/",
	"https://securitylab.github.com/",
	"https://plugins.trac.wordpress.org/",

	// These are known platform with articles
	"https://hackmd.io/",
	"https://medium.com/",
}

// Blogs or...
var knownValidatedButNotTrustedSources = []string{
	// old
	"https://wpvulndb.com/",
	"https://packetstormsecurity.com/",
	"https://packetstormsecurity.org/",

	// too generic
	"https://gitlab.com/",
	"https://www.youtube.com/", "https://youtu.be/",
	"https://docs.google.com/", "https://drive.google.com/",
	"https://gist.github.com/",
	"https://gitee.com/",

	// Aggregators with multiple endpoints
	"https://github.com/BlockChainsSecurity/EtherTokens/",

	// it's a personal choice, but open to changes
	"https://www.syss.de/",
	"https://git.kernel.org/",
	"https://codevigilant.com/",
	"https://pierrekim.github.io/",
	"https://blog.nintechnet.com/",
	"https://blog.securityevaluators.com/",
	"https://aluigi.altervista.org/",
	"https://bugzilla.mozilla.org/show_bug.cgi",
	"https://bugzilla.redhat.com/show_bug.cgi",
	"https://blogs.gentoo.org/", "bugs.gentoo.org/",
	"https://marc.info/",
	"https://www.mend.io/vulnerability-database/",
	"https://www.whitesourcesoftware.com/",
	"https://www.vulnerability-lab.com/",
	"https://www.zeroscience.mk/",
	"https://evuln.com/",
	"https://www.evuln.com/",
	"https://securityreason.com/", "https://cxsecurity.com/",
	"https://crbug.com/", "https://bugs.chromium.org/", "https://issues.chromium.org/",
	"https://code.google.com/", // some are dead
	"https://fluidattacks.com/",
	"https://antoniocannito.it/",
	"https://jira.xwiki.org/",
	"https://bugs.debian.org/",
	"https://bugs.php.net/",
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
	"https://www.foxitsoftware.com/support/security-bulletins.html",                   // junk
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
	"https://h20566.www2.hpe.com/",                                                    // dead
	"https://www.securityfocus.com/",                                                  // dead
	"https://downloads.securityfocus.com/",                                            // dead
	"https://online.securityfocus.com/",                                               // dead
	"https://docs.microsoft.com/en-us/security-updates/",                              // vuln details
	"https://www.vmware.com/",                                                         // junk
	"https://www.mandriva.com/",                                                       // junk
	"https://www.cisco.com/warp/",                                                     // junk
	"https://cdn.kernel.org/pub/linux/kernel/",                                        // junk
	"https://www.redhat.com/support/errata/",                                          // junk
	"https://sourceforge.net/",                                                        // nothing
	"https://mattermost.com/security-updates/",                                        // nothing
	"https://www-01.ibm.com/",                                                         // vuln details
	"https://www.mozilla.org/security/",                                               // vuln details
	"https://oval.cisecurity.org/repository/",                                         // dead
	"https://www.osvdb.org/",                                                          // dead
	"https://osvdb.org/",                                                              // dead
	"https://archives.neohapsis.com/",                                                 // dead
	"https://secunia.com/",                                                            // dead
	"https://www.securitytracker.com/",                                                // dead
	"https://securitytracker.com/",                                                    // dead
	"https://www.htbridge.com/",                                                       // dead
	"https://lists.grok.org.uk/",                                                      // dead
	"https://www.wordfence.com/vulnerability-advisories/",                             // only this endpoint
	"https://antoniocannito.it/?p=137#uxss",                                           // junk
	"https://www.elastic.co/community/security",                                       // junk
	"https://ffmpeg.org/security.html",                                                // junk
	"https://explore.zoom.us/en/trust/security/security-bulletin/",                    // junk
	"https://helpx.adobe.com/security/products/acrobat/",                              // junk
	"https://www.manageengine.com/",                                                   // junk
	"https://github.com/tats/w3m/blob/master/ChangeLog",                               // junk
	"https://blog.jetbrains.com/blog/2021/05/07/jetbrains-security-bulletin-q1-2021/", // junk
}

func InspectAggregatorURL(url string, cveId string, quick bool) (string, float64) {
	var found bool
	var trusted float64
	url = strings.Replace(url, "http://", "https://", -1)
	for _, banned := range knownForbiddenSourcesPrefix {
		if strings.HasPrefix(url, banned) {
			return "", trusted
		}
	}
	// No advisory identifier in the URL (but useful when there is one)
	if url == "https://cert.vde.com/en-us/advisories/" {
		return "", trusted
	}
	if url == "https://www.coresecurity.com/advisories" {
		return "", trusted
	}
	if url == "https://www.gruppotim.it/it/footer/red-team.html" {
		// One CVE with a PoC, 75 others listed without one
		if cveId == "CVE-2024-52949" {
			return url, 0.5
		}
		return "", trusted
	}
	// Nothing useful in the context of PoC/Exploits
	if url == "https://docs.google.com/spreadsheets/d/1t5GXwjw82SyunALVJb2w0zi3FoLRIkfGPc7AMjRF0r4/edit?usp=sharing" {
		return "", trusted
	}
	// Renamed
	if strings.HasPrefix(url, "https://antoniocannito.it/phpkb1") {
		url = strings.Replace(url, "https://antoniocannito.it/phpkb1", "https://antoniocannito.it/en/phpkb", 1)
	}

	// Common Repository (already index, but trickest often has a few
	// more than even exploit-db did not properly index)
	if strings.HasPrefix(url, "https://www.exploit-db.com") {
		url = strings.TrimSuffix(url, "/")
		found = true
		trusted = 0.5
	}

	// These are big CVEs databases
	// They may contain dead links, todos (false positives), etc.
	// In practice, we should directly scrap them (but too much data is too much)
	if !found {
		for _, dbURL := range knownValidatedSources {
			if dbURL == url {
				found = true
				trusted = 0.9
				break
			}
		}
	}
	if !found {
		for _, dbURL := range knownValidatedSourcesPrefix {
			if strings.HasPrefix(url, dbURL) {
				found = true
				trusted = 0.7
				break
			}
		}
	}

	// Find CVE in the name
	if !found && strings.Contains(url, "CVE-") {
		found = cveRegex.MatchString(url)
	}

	if !found {
		for _, dbURL := range knownValidatedButNotTrustedSources {
			if strings.HasPrefix(url, dbURL) {
				found = true
				trusted = 0.4
				break
			}
		}
	}

	if !found && strings.Contains(url, "https://github.com/") {
		if strings.Contains(url, "/issues/") {
			found = true
			trusted = 0.4
		} else if strings.HasSuffix(url, ".md") {
			found = true
			trusted = 0.4
		} else if strings.Contains(url, "/security/advisories/") {
			found = true
			trusted = 0.4
		}
	}

	// Deny all
	if !quick && !found {
		url = ""
	}

	return url, trusted
}

func ComputeValidatedSources() (sources []string) {
	for _, knownURL := range knownValidatedSources {
		parsedUrl, err := url.Parse(knownURL)
		if err != nil {
			continue
		}
		sources = append(sources, parsedUrl.Host)
	}
	for _, knownURL := range knownValidatedSourcesPrefix {
		parsedUrl, err := url.Parse(knownURL)
		if err != nil {
			continue
		}
		sources = append(sources, parsedUrl.Host)
	}
	for _, knownURL := range knownValidatedButNotTrustedSources {
		parsedUrl, err := url.Parse(knownURL)
		if err != nil {
			continue
		}
		sources = append(sources, parsedUrl.Host)
	}
	return
}
