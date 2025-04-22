# Open PoCs [<img src="https://github.com/oneaudit/openpoc/actions/workflows/main.yaml/badge.svg" alt="" align="right">](https://github.com/oneaudit/openpoc/actions/workflows/main.yaml)

Aggregates multiple data sources related to CVE exploits/PoC.

<table>
  <tr>
    <td align="center">
<img alt="" width="400" src=".github/images/stats_example.svg" alt=""/>
</td>
<td align="center">
<img alt="" width="400" src=".github/images/stats_example.svg" alt=""/>
</td>
<td></td>
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

It would be good to improve this source, such as by testing links or adding dates.

## Nomisec Repository 👑

[Nomisec](https://github.com/nomi-sec/PoC-in-GitHub/) is another popular open-source project for monitoring exploits.<br>
 While their content is more limited than Trickest, almost all of their links are relevant.

```
> Source: https://github.com/nomi-sec/PoC-in-GitHub/
> Update schedule: every 6 hours
```

## Exploit Database 🪲

[Exploit Database](https://www.exploit-db.com/) is a well-known and popular website with a large collection of PoCs.<br>
Their database is available in CSV format and is hosted on GitLab.

```
> Source: https://gitlab.com/exploit-database/exploitdb.git
> Update schedule: every 24 hours
```

One issue with this source is that some exploits are not linked to a CVE, or the linked CVE is not properly formatted. This affects a small part of their database (<1%). This project attempts to address that by using multiple sources to indirectly fetch and parse the exploit database.

## In The Wild API 🫏

[InTheWild](https://inthewild.io/) is a lesser-known but useful source for finding rare and hard-to-find exploits.<br>
Their database was available on GitHub, and the API is still available for free use.

```
> Source: https://inthewild.io/api/exploits?limit=1
> Update schedule: once a week
```

## License 📄

This project is licensed under the MIT License.<br>
You are free to use, modify, and distribute this software with proper attribution. See the [LICENSE](LICENSE) file for full details.
