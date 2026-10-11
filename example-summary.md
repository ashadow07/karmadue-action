## KarmaDue guard: FAIL

❌ Blocking: a malicious-code report or a configured advisory rule matched

Scanned changes since the pull request base 511f59b. Checked 7 items (5 package versions, 2 MCP servers) from 4 files. OSV.dev lookup: ok.

| Result | Package or server | Version | Where | Finding | Evidence |
|---|---|---|---|---|---|
| ❌ fail | `npm:tensorlake` | 0.5.144 | package-lock.json, package.json | Malicious-code report MAL-2026-17650 covering 0.5.144 | [1](https://osv.dev/vulnerability/MAL-2026-17650) |
| ❌ fail | `PyPI:agent-vx` | 0.1.0 | requirements.txt | Malicious-code report MAL-2026-17755 covering 0.1.0 | [1](https://osv.dev/vulnerability/MAL-2026-17755) |
| ❌ fail | `npm:postmark-mcp` via MCP server "postmark" (npx) | — | .mcp.json | Malicious-code report MAL-2025-47604 (all versions) | [1](https://osv.dev/vulnerability/MAL-2025-47604) |
| ⚠️ warn | `npm:lodash` | 4.17.15 | package-lock.json, package.json | 6 published advisories cover 4.17.15: GHSA-29mw-wpgm-hmr9, GHSA-35jh-r3h4-6jhm, GHSA-f23m-r3pf-42rh, GHSA-p6mc-m468-83gw, GHSA-r5fr-rjxr-66jc, GHSA-xxjr-mmjv-4gpg | [1](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) [2](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) [3](https://osv.dev/vulnerability/GHSA-f23m-r3pf-42rh) [4](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) |
| ⚠️ warn | `PyPI:requests` | 2.32.3 | requirements.txt | 4 published advisories cover 2.32.3: GHSA-9hjg-9r4m-mvj7, GHSA-gc5v-m9x4-r6x2, PYSEC-2026-1872, PYSEC-2026-2275 | [1](https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7) [2](https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2) [3](https://osv.dev/vulnerability/PYSEC-2026-1872) [4](https://osv.dev/vulnerability/PYSEC-2026-2275) |

<details><summary>2 notes (not checked or no exact version)</summary>

- `npm:postmark-mcp` (.mcp.json): No exact version (unpinned), so advisories for a specific version were not checked
- MCP `docs` (.mcp.json): Remote MCP server https://mcp.example.com/mcp: no package to check; see whether KarmaDue lists it at https://karmadue.expo.app/badge

</details>

**What this does not prove.** A pass means KarmaDue's data and OSV.dev had no malicious-code report or advisory for these exact versions, and KarmaDue recorded no owner, license or tool-list change for the catalog tools they map to. It is not a security review, says nothing about packages not in that data, and doesn't check transitive dependencies a lockfile doesn't list. Change records started 2026-10-11.

Data: [malicious-package list](https://karmadue.expo.app/lists/malicious-packages.json) · [changes feed](https://karmadue.expo.app/feeds/changes.json) · [how this works](https://karmadue.expo.app/docs/feeds.md#github-action). Network calls made by this action: 1 lookup to the KarmaDue API, nothing else.
