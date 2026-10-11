// Diffing, the KarmaDue lookup and the verdicts. Pure functions plus an injectable fetch, so tests run offline.
import { fileKind, parseFile, parseMcpConfig, pyNorm } from "./parsers.mjs";

export const keyOf = (p) => `${p.ecosystem}:${p.ecosystem === "PyPI" ? pyNorm(p.name) : p.name}`;
const exactish = (p) => (p.ecosystem === "npm" ? (/^\d+\.\d+\.\d+/.test(p.version ?? "") ? p.version : null) : (/^\d/.test(p.version ?? "") ? p.version : null));

/** Packages and MCP servers that `after` adds or changes compared with `before` (both raw file texts; before may be ""). */
export function diffFile(path, before, after, scanAll = false) {
  const kind = fileKind(path);
  if (!kind || after == null) return { packages: [], servers: [] };
  if (kind === "mcp") {
    const old = new Map(parseMcpConfig(before ?? "").map((s) => [s.name, s]));
    const servers = parseMcpConfig(after).filter((s) => scanAll || !old.has(s.name) || old.get(s.name).identity !== s.identity)
      .map((s) => ({ ...s, file: path, change: old.has(s.name) ? "changed" : "added", previous: old.get(s.name) ?? null }));
    return { packages: [], servers };
  }
  const oldSet = new Set(parseFile(kind, before ?? "").map((p) => `${keyOf(p)}@${p.version ?? p.spec ?? ""}`));
  const oldVersions = new Map();
  for (const p of parseFile(kind, before ?? "")) oldVersions.set(keyOf(p), p.version ?? p.spec ?? null);
  const packages = parseFile(kind, after).filter((p) => scanAll || !oldSet.has(`${keyOf(p)}@${p.version ?? p.spec ?? ""}`))
    .map((p) => ({ ...p, version: exactish(p), file: path, change: oldVersions.has(keyOf(p)) ? "updated" : "added", from: oldVersions.get(keyOf(p)) ?? null }));
  return { packages, servers: [] };
}

/** One entry per ecosystem/name/version, remembering every file it came from. */
export function mergePackages(list) {
  const map = new Map();
  for (const p of list) {
    const k = `${keyOf(p)}@${p.version ?? ""}`;
    const e = map.get(k);
    if (e) { if (!e.files.includes(p.file)) e.files.push(p.file); if (!e.from && p.from) e.from = p.from; if (p.via && !e.via) e.via = p.via; }
    else map.set(k, { ecosystem: p.ecosystem, name: p.name, version: p.version ?? null, spec: p.spec, change: p.change, from: p.from ?? null, files: [p.file], via: p.via ?? null });
  }
  // A versionless entry (package.json range) is dropped when the same package has an exact version from a lockfile.
  const withVersion = new Set([...map.values()].filter((p) => p.version).map(keyOf));
  return [...map.values()].filter((p) => p.version || !withVersion.has(keyOf(p)));
}

export async function lookup(apiUrl, packages, { osv = true, fetchImpl = fetch } = {}) {
  const results = [];
  for (let i = 0; i < packages.length; i += 500) {
    const chunk = packages.slice(i, i + 500);
    const r = await fetchImpl(`${apiUrl.replace(/\/$/, "")}/packages/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "karmadue-action/0.1" },
      body: JSON.stringify({ osv, packages: chunk.map((p) => ({ ecosystem: p.ecosystem, name: p.name, version: p.version })) }),
    });
    if (!r.ok) throw new Error(`KarmaDue API answered HTTP ${r.status}`);
    const j = await r.json();
    if (!Array.isArray(j.results) || j.results.length !== chunk.length) throw new Error("KarmaDue API returned an unexpected body");
    results.push(...j.results.map((x) => ({ ...x, osv_status: j.osv })));
  }
  return results;
}

const osvLink = (id) => `https://osv.dev/vulnerability/${id}`;

/** Findings for one package from the API result. level: fail | warn | info. */
export function judge(pkg, res, cfg) {
  const out = [];
  const where = { files: pkg.files, via: pkg.via };
  const mal = (res?.malicious ?? []);
  const osvMal = res?.osv?.malicious ?? [];
  const malHit = mal.filter((m) => m.versions === "all" || (pkg.version && Array.isArray(m.versions) && m.versions.includes(pkg.version)));
  const malMaybe = mal.filter((m) => !malHit.includes(m) && !pkg.version);
  const malIds = new Set([...malHit.map((m) => m.id), ...osvMal]);
  if (malIds.size) out.push({ level: "fail", kind: "malicious", ...where, pkg, text: `Malicious-code report${malIds.size > 1 ? "s" : ""} ${[...malIds].join(", ")}${pkg.version ? ` covering ${pkg.version}` : " (all versions)"}`, evidence: [...malIds].map(osvLink) });
  if (malMaybe.length) out.push({ level: "warn", kind: "malicious-other-version", ...where, pkg, text: `Malicious-code report ${malMaybe.map((m) => m.id).join(", ")} covers version${malMaybe.flatMap((m) => m.versions).length > 1 ? "s" : ""} ${malMaybe.flatMap((m) => m.versions).join(", ")}; this entry has no exact version, so check what it resolves to`, evidence: malMaybe.map((m) => osvLink(m.id)) });
  if (cfg.onAdvisory !== "ignore" && pkg.version) {
    const kdV = (res?.vulnerabilities ?? []).filter((v) => v.affects_version === true).map((v) => v.id);
    const ids = [...new Set([...kdV, ...(res?.osv?.vulnerabilities ?? [])])];
    if (ids.length) {
      const shown = ids.slice(0, 8);
      out.push({ level: cfg.onAdvisory === "fail" ? "fail" : "warn", kind: "advisory", ...where, pkg, text: `${ids.length} published advisor${ids.length > 1 ? "ies cover" : "y covers"} ${pkg.version}: ${shown.join(", ")}${ids.length > shown.length ? ", …" : ""}`, evidence: shown.map(osvLink) });
    }
  }
  if (cfg.onChange !== "ignore") {
    for (const c of res?.catalog ?? []) {
      const changes = c.changes_30d ?? [];
      if (changes.length) out.push({ level: "warn", kind: "changed", ...where, pkg, text: `KarmaDue recorded ${changes.map((x) => `${x.kind} change (${String(x.detected_at).slice(0, 10)}: ${JSON.stringify(x.before)} → ${JSON.stringify(x.after)})`).join("; ")} for ${c.resource_id}`, evidence: [c.passport, ...changes.flatMap((x) => (Array.isArray(x.evidence) ? x.evidence.map((e) => e.url).filter(Boolean) : []))] });
    }
  }
  if (!pkg.version) out.push({ level: "info", kind: "no-version", ...where, pkg, text: `No exact version (${pkg.spec || "unpinned"}), so advisories for a specific version were not checked`, evidence: [] });
  return out;
}

export function evaluate(packages, servers, results, cfg) {
  const findings = [];
  packages.forEach((p, i) => findings.push(...judge(p, results[i], cfg)));
  for (const s of servers) {
    if (s.url && !s.command) findings.push({ level: "info", kind: "remote-server", files: [s.file], server: s, text: `Remote MCP server ${s.url}: no package to check; see whether KarmaDue lists it at https://karmadue.expo.app/badge`, evidence: [] });
    else if (s.launch?.docker) findings.push({ level: "info", kind: "docker-server", files: [s.file], server: s, text: `MCP server runs Docker image ${s.launch.docker}: images are not checked by this action`, evidence: [] });
    else if (!s.launch) findings.push({ level: "info", kind: "unknown-launch", files: [s.file], server: s, text: `MCP server launches \`${[s.command, ...s.args].join(" ")}\`: not a package runner this action understands (npx, pnpm/yarn dlx, bunx, uvx, pipx run, docker)`, evidence: [] });
  }
  const count = (lvl, kind) => findings.filter((f) => f.level === lvl && (!kind || f.kind === kind)).length;
  const result = count("fail") ? "fail" : count("warn") ? "warn" : "pass";
  return {
    result, findings,
    counts: { malicious: findings.filter((f) => f.kind === "malicious").length, advisories: findings.filter((f) => f.kind === "advisory").length, changes: findings.filter((f) => f.kind === "changed").length, checked: packages.length + servers.length },
  };
}

/** Packages that MCP servers launch, tagged with the server they came from. */
export function serverPackages(servers) {
  return servers.filter((s) => s.launch?.ecosystem).map((s) => ({
    ecosystem: s.launch.ecosystem, name: s.launch.name,
    version: s.launch.ecosystem === "npm" ? (/^\d+\.\d+\.\d+/.test(s.launch.version ?? "") ? s.launch.version : null) : (/^\d/.test(s.launch.version ?? "") ? s.launch.version : null),
    spec: s.launch.version ?? "unpinned", file: s.file, change: s.change, via: `MCP server "${s.name}" (${s.launch.runner})`,
  }));
}

const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const icon = { fail: "❌ fail", warn: "⚠️ warn", info: "ℹ️ note" };

export function summaryMarkdown(ev, ctx) {
  const lines = [];
  const head = { pass: "✅ No malicious packages, exact-version advisories or recent changes found", warn: "⚠️ Warnings: review before merging", fail: "❌ Blocking: a malicious-code report or a configured advisory rule matched" }[ev.result];
  lines.push(`## KarmaDue guard: ${ev.result.toUpperCase()}`, "", head, "");
  lines.push(`Scanned ${ctx.scope}. Checked ${ev.counts.checked} item${ev.counts.checked === 1 ? "" : "s"} (${ctx.packageCount} package version${ctx.packageCount === 1 ? "" : "s"}, ${ctx.serverCount} MCP server${ctx.serverCount === 1 ? "" : "s"}) from ${ctx.files.length} file${ctx.files.length === 1 ? "" : "s"}. OSV.dev lookup: ${ctx.osv}.`, "");
  const rank = { fail: 0, warn: 1 };
  const shown = ev.findings.filter((f) => f.level !== "info").sort((a, b) => rank[a.level] - rank[b.level]);
  if (shown.length) {
    lines.push("| Result | Package or server | Version | Where | Finding | Evidence |", "|---|---|---|---|---|---|");
    for (const f of shown) {
      const who = f.pkg ? `\`${esc(f.pkg.ecosystem)}:${esc(f.pkg.name)}\`${f.via ? ` via ${esc(f.via)}` : ""}` : `MCP \`${esc(f.server?.name)}\``;
      const ver = f.pkg?.version ? `${f.pkg.from && f.pkg.from !== f.pkg.version ? `${esc(f.pkg.from)} → ` : ""}${esc(f.pkg.version)}` : "—";
      lines.push(`| ${icon[f.level]} | ${who} | ${ver} | ${esc((f.files ?? []).join(", "))} | ${esc(f.text)} | ${(f.evidence ?? []).filter(Boolean).slice(0, 4).map((u, i) => `[${i + 1}](${u})`).join(" ")} |`);
    }
    lines.push("");
  }
  const notes = ev.findings.filter((f) => f.level === "info");
  if (notes.length) {
    lines.push(`<details><summary>${notes.length} note${notes.length === 1 ? "" : "s"} (not checked or no exact version)</summary>`, "");
    for (const f of notes.slice(0, 200)) lines.push(`- ${f.pkg ? `\`${esc(f.pkg.ecosystem)}:${esc(f.pkg.name)}\`` : `MCP \`${esc(f.server?.name)}\``} (${esc((f.files ?? []).join(", "))}): ${esc(f.text)}`);
    if (notes.length > 200) lines.push(`- …and ${notes.length - 200} more`);
    lines.push("", "</details>", "");
  }
  if (ctx.error) lines.push(`> **KarmaDue lookup failed:** ${esc(ctx.error)}. Nothing was checked.`, "");
  lines.push("**What this does not prove.** A pass means KarmaDue's data and OSV.dev had no malicious-code report or advisory for these exact versions, and KarmaDue recorded no owner, license or tool-list change for the catalog tools they map to. It is not a security review, says nothing about packages not in that data, and doesn't check transitive dependencies a lockfile doesn't list. Change records started 2026-10-11.", "");
  lines.push(`Data: [malicious-package list](https://karmadue.expo.app/lists/malicious-packages.json) · [changes feed](https://karmadue.expo.app/feeds/changes.json) · [how this works](https://karmadue.expo.app/docs/feeds.md#github-action). Network calls made by this action: ${ctx.calls} lookup${ctx.calls === 1 ? "" : "s"} to the KarmaDue API, nothing else.`);
  return lines.join("\n") + "\n";
}
