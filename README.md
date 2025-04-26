# Open PoCs [<img src="https://github.com/oneaudit/openpoc/actions/workflows/main.yaml/badge.svg" alt="" align="right">](https://github.com/oneaudit/openpoc/actions/workflows/main.yaml)

Aggregates multiple data sources related to CVE exploits/PoC. [Please read the license terms](#license-).

<table>
  <tr>
    <th align="center">2025</th>
    <th align="center">2024</th>
  </tr>
  <tr>
    <td align="center">
      <img alt="" width="400" src=".github/images/2025.svg" alt=""/>
    </td>
    <td align="center">
      <img alt="" width="400" src=".github/images/2024.svg" alt=""/>
    </td>
  </tr>
  <tr>
    <th align="center">2023</th>
    <th align="center">2022</th>
  </tr>
  <tr>
    <td align="center">
      <img alt="" width="400" src=".github/images/2023.svg" alt=""/>
    </td>
    <td align="center">
      <img alt="" width="400" src=".github/images/2022.svg" alt=""/>
    </td>
  </tr>
</table>

## Trickest Repository 🗺️

[Trickest](https://github.com/trickest/cve) is one of the most popular open-source projects for monitoring exploits.<br>
The main issue with their database is that it contains many dead links and irrelevant content.<br>
Aside from the links in `references.txt` and a few whitelisted sources, we are skipping around 90% of their links.<br>

```
> Source: https://github.com/trickest/cve
> Source: https://github.com/trickest/cve/blob/main/references.txt
> Update schedule: every 24 hours
```

It would be good to improve this source, such as by testing links or adding dates as there are none.

## Nomisec Repository 👑

[Nomisec](https://github.com/nomi-sec/PoC-in-GitHub/) is another popular open-source project for monitoring exploits.<br>
 While their content is more limited than Trickest, almost all of their links are relevant.

```
> Source: https://github.com/nomi-sec/PoC-in-GitHub/
> Update schedule: every 6 hours
```

A relatively similar resource is: [CyberWarZone](https://cyberwarzone.com/githubfeed).

## Exploit Database 🪲

[Exploit Database](https://www.exploit-db.com/) is a well-known and popular website with a large collection of PoCs.<br>
Their database is available in CSV format and is hosted on GitLab.

```
> Source: https://gitlab.com/exploit-database/exploitdb.git
> Update schedule: every 24 hours
```

One issue with this source is that some exploits are not linked to a CVE, or the linked CVE is not properly formatted. This affects a small part of their database (<1%).

## In The Wild API 🫏

[InTheWild](https://inthewild.io/) is a lesser-known but useful source for finding rare and hard-to-find exploits.<br>
Their database was available on GitHub, and the API is still available for free use.

```
> Source: https://inthewild.io/api/exploits?limit=1
> Update schedule: once a week
```

## Nuclei Repository 🐲

XXX

```
> Source: XXX
> Update schedule: xxxx
```

## Metasploit Repository 🚢

XXX

```
> Source: XXX
> Update schedule: xxxx
```

## Want more ? 🔍

A few candidates indirectly scrapped by Trickest:

* `seclists.org`
* `wpscan.com`, `wpvulndb.com`
* `packetstorm.news`
* `security.snyk.io`, `snyk.io/vuln/`
* `talosintelligence.com`
* `huntr.com`, `huntr.dev`
* `hackerone.com`
* `www.tenable.com`
* `openwall.com`
* `securitylab.github.com`
* `medium.com`
* `vulnerability-lab.com`
* `whitesourcesoftware.com`
* `osv.dev`, `osvdb.org`

## How To Add A New Source

The process is not straightforward but relatively easy:

* ✅ Create a type implementing `OpenPocMetadata`
* ✅ Add a field inside `AggregatorResult`
* ✅ Edit `AggregatorResult#NewAggregatorResult` to create a default empty array
* ✅ Edit `AggregatorResult#ComputeOpenPoc` to merge the new results in `openpoc`
* ✅ Edit `AggregatorResult#Sort` to sort the new results
* ✅ Edit `MergeAggregatorResults` to load cached results as a fallback
* ✅ Add the logic inside `main.go` to generate results
* ✅ Bump the version inside `main.go`

## License 📄

This project is licensed under the GNU GPL v3.0 License.<br>
You are free to use, modify, and distribute this software with proper attribution. See the [LICENSE](LICENSE) file for full details.
