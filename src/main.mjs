// Entry point for the GitHub Action (node20). No dependencies, no token, no telemetry: the only network calls are the lookups to the
// KarmaDue API. Git is used read-only to find what the pull request (or push) changed.
import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { fileKind } from "./parsers.mjs";
import { diffFile, evaluate, lookup, mergePackages, serverPackages, summaryMarkdown } from "./core.mjs";

const input = (name, def = "") => {
  const v = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`];
  return v === undefined || v === "" ? def : v.trim();
};

function git(cwd, args, opts = {}) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 256 * 1024 * 1024, ...opts });
}
const hasCommit = (cwd, sha) => { try { git(cwd, ["cat-file", "-e", `${sha}^{commit}`]); return true; } catch { return false; } };

export function resolveBase(cwd, env, explicit) {
  if (explicit) return { sha: explicit, why: `base-ref ${explicit}` };
  let event = {};
  try { if (env.GITHUB_EVENT_PATH && existsSync(env.GITHUB_EVENT_PATH)) event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")); } catch { /* none */ }
  const pr = event.pull_request ?? event.merge_group;
  if (pr?.base?.sha) return { sha: pr.base.sha, why: `pull request base ${pr.base.sha.slice(0, 7)}` };
  if (event.merge_group?.base_sha) return { sha: event.merge_group.base_sha, why: `merge group base ${event.merge_group.base_sha.slice(0, 7)}` };
  if (event.before && !/^0+$/.test(event.before)) return { sha: event.before, why: `previous commit ${event.before.slice(0, 7)}` };
  return null;
}

function ensureCommit(cwd, sha) {
  if (hasCommit(cwd, sha)) return true;
  try { git(cwd, ["fetch", "--no-tags", "--depth=1", "origin", sha]); } catch { /* fall through */ }
  return hasCommit(cwd, sha);
}

function listFiles(cwd, base) {
  if (base) return git(cwd, ["diff", "--name-only", "--diff-filter=AMR", base, "HEAD"]).split("\n").filter(Boolean);
  return git(cwd, ["ls-files"]).split("\n").filter(Boolean);
}
const showAt = (cwd, sha, path) => { try { return git(cwd, ["show", `${sha}:${path}`]); } catch { return ""; } };

function annotate(f) {
  if (f.level === "info") return;
  const file = (f.files ?? [])[0];
  const title = f.kind === "malicious" ? "Malicious package" : f.kind === "advisory" ? "Advisory for this version" : f.kind === "changed" ? "Changed recently" : "KarmaDue";
  const msg = `${f.pkg ? `${f.pkg.ecosystem}:${f.pkg.name}${f.pkg.version ? `@${f.pkg.version}` : ""}` : f.server?.name}: ${f.text} ${(f.evidence ?? [])[0] ?? ""}`.replace(/%/g, "%25").replace(/\r?\n/g, "%0A");
  process.stdout.write(`::${f.level === "fail" ? "error" : "warning"} ${file ? `file=${file},` : ""}title=${title}::${msg}\n`);
}

export async function run({ cwd = process.cwd(), env = process.env, fetchImpl = fetch, log = (s) => process.stdout.write(s + "\n") } = {}) {
  const cfg = {
    onAdvisory: ["warn", "fail", "ignore"].includes(input("on-advisory", "warn")) ? input("on-advisory", "warn") : "warn",
    onChange: input("on-change", "warn") === "ignore" ? "ignore" : "warn",
    scan: input("scan", "diff") === "all" ? "all" : "diff",
    osv: input("osv", "true") !== "false",
    failOnError: input("fail-on-error", "false") === "true",
    api: input("api-url", "https://ogogoizwsfaduzehkshb.supabase.co/functions/v1/feeds/v1"),
  };
  let base = null, scope = "every dependency file in the repository";
  if (cfg.scan === "diff") {
    const b = resolveBase(cwd, env, input("base-ref"));
    if (b && ensureCommit(cwd, b.sha)) { base = b.sha; scope = `changes since the ${b.why}`; }
    else log(`::notice title=KarmaDue::${b ? `Base commit ${b.sha} is not available` : "No pull request or push base found"}; scanning every dependency file instead.`);
  }
  const files = listFiles(cwd, base).filter((p) => fileKind(p));
  const pkgs = [], servers = [];
  for (const path of files) {
    const after = existsSync(join(cwd, path)) ? readFileSync(join(cwd, path), "utf8") : null;
    const before = base ? showAt(cwd, base, path) : "";
    const d = diffFile(path, before, after, !base);
    pkgs.push(...d.packages); servers.push(...d.servers);
  }
  const packages = mergePackages([...pkgs, ...serverPackages(servers)]);
  let results = [], error = null, calls = 0;
  if (packages.length) {
    try { calls = Math.ceil(packages.length / 500); results = await lookup(cfg.api, packages, { osv: cfg.osv, fetchImpl }); }
    catch (e) { error = String(e?.message ?? e); }
  }
  const ev = error ? { result: cfg.failOnError ? "fail" : "warn", findings: [], counts: { malicious: 0, advisories: 0, changes: 0, checked: 0 } } : evaluate(packages, servers, results, cfg);
  const osvStatus = !cfg.osv ? "off" : results[0]?.osv_status ?? (packages.length ? "not reached" : "not needed");
  const md = summaryMarkdown(ev, { scope, files, packageCount: packages.length, serverCount: servers.length, osv: osvStatus, error, calls });
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md);
  else log(md);
  for (const f of ev.findings) annotate(f);
  if (error) log(`::warning title=KarmaDue::Lookup failed: ${error}`);
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `result=${ev.result}\nmalicious=${ev.counts.malicious}\nadvisories=${ev.counts.advisories}\nchanges=${ev.counts.changes}\nchecked=${ev.counts.checked}\n`);
  log(`KarmaDue guard: ${ev.result} (${ev.counts.checked} checked, ${ev.counts.malicious} malicious, ${ev.counts.advisories} advisory, ${ev.counts.changes} changed)`);
  return { ...ev, markdown: md, files, packages, servers };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  run().then((r) => { process.exitCode = r.result === "fail" ? 1 : 0; }).catch((e) => { process.stdout.write(`::error title=KarmaDue::${String(e?.stack ?? e).replace(/\r?\n/g, "%0A")}\n`); process.exitCode = 1; });
}
