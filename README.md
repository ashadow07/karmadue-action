# KarmaDue guard (GitHub Action)

Checks the packages and MCP servers a pull request adds or changes. It fails on published malicious-code reports, and warns (or fails, if you configure it) on advisories that cover the exact version. It also warns when KarmaDue recorded an owner, license or MCP tool-list change for the tool in the last 30 days. Every finding in the job summary links to its evidence.

```yaml
- uses: ashadow07/karmadue-action@v1
```

A full workflow is in [examples/karmadue.yml](examples/karmadue.yml). It needs no token, no secrets and no write permissions (`contents: read` is enough).

## What it scans

Only files changed in the pull request (or since the previous commit on a push). Use `scan: all` to check everything.

| Files | What is read |
| --- | --- |
| `package.json` | dependencies, devDependencies, optionalDependencies, peerDependencies (exact pins get a version; ranges are checked by name) |
| `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v6 to v9) | every resolved package and version |
| `requirements*.txt`, `requirements/*.txt`, `pyproject.toml` (PEP 621 and Poetry), `poetry.lock`, `uv.lock`, `Pipfile.lock` | Python packages and pinned versions |
| `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` (JSONC is fine) | MCP servers whose command, arguments or URL were added or changed; the package a server launches with `npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `npm exec`, `uvx`, `uv tool run` or `pipx run` is checked like a dependency |

## Rules

| Finding | Default | Input |
| --- | --- | --- |
| Malicious-code report (OpenSSF via OSV.dev) covering this version or all versions | **fail** | always on |
| Malicious-code report for other versions, when the entry has no exact version | warn | always on |
| Advisory covering the exact version (KarmaDue data plus OSV.dev) | warn | `on-advisory: warn \| fail \| ignore` |
| KarmaDue recorded an owner, license, MCP tool-list, archive or terms change in the last 30 days | warn | `on-change: warn \| ignore` |
| Remote (URL) MCP servers, Docker images, unknown launchers, unpinned versions | note in the summary | — |
| KarmaDue API unreachable | warn | `fail-on-error: true` to fail |

Outputs: `result` (pass, warn or fail), `malicious`, `advisories`, `changes`, `checked`.

## Network and privacy

The action makes one kind of network call: `POST <api-url>/packages/check` with the ecosystem, name and version of each added or changed package, 500 per request. No token, repository name, file contents or other telemetry is sent. The KarmaDue API answers from its own data. Unless you set `osv: false`, the API also queries OSV.dev for those exact versions on its side. Git is used read-only, and the action may `git fetch` the base commit when the checkout is shallow.

## What a pass does and doesn't mean

A pass means that KarmaDue's data and OSV.dev had no malicious-code report or advisory for these exact versions, and that KarmaDue recorded no recent owner, license or tool-list change for the catalog tools they map to. It is not a security review. KarmaDue's malicious set covers npm and PyPI packages related to agents, MCP and AI tooling, and OSV.dev covers the rest. Transitive dependencies are checked only when a lockfile lists them. Change records started on 2026-10-11, so the "changed" rule has little history yet.

## Example summary

See [example-summary.md](example-summary.md). It is a real run against the live API on the test fixture: `tensorlake@0.5.144`, `agent-vx==0.1.0` and an MCP server launching `npx -y postmark-mcp` fail; `lodash@4.17.15` and `requests==2.32.3` warn on advisories; a remote MCP server is noted.

## Development

```sh
npm test            # unit + end-to-end tests with a fake API (no network)
npm run test:live   # also runs the end-to-end fixture against the live KarmaDue API
```

MIT licensed. Data sources: https://karmadue.expo.app/docs/feeds.md
