// End to end: a real git repository with a base and a head commit, the action's run() with GitHub's env vars, and a fake API
// (or the live API with KD_LIVE=1).
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/main.mjs";

const FX = new URL("./fixtures/", import.meta.url).pathname;

function makeRepo() {
  const dir = mkdtempSync(join(tmpdir(), "kd-action-"));
  const g = (...a) => execFileSync("git", a, { cwd: dir, encoding: "utf8" }).trim();
  g("init", "-q", "-b", "main");
  g("config", "user.email", "t@example.com"); g("config", "user.name", "t");
  cpSync(join(FX, "repo-base"), dir, { recursive: true });
  g("add", "-A"); g("commit", "-qm", "base");
  const base = g("rev-parse", "HEAD");
  cpSync(join(FX, "repo-head"), dir, { recursive: true });
  g("add", "-A"); g("commit", "-qm", "head");
  const event = join(dir, "..", `event-${Date.now()}.json`);
  writeFileSync(event, JSON.stringify({ pull_request: { base: { sha: base } } }));
  return { dir, base, event, summary: join(dir, "..", `summary-${Date.now()}.md`), output: join(dir, "..", `output-${Date.now()}.txt`) };
}

function fakeApi(seen) {
  return async (url, init) => {
    seen.push({ url, headers: init.headers });
    const { packages } = JSON.parse(init.body);
    const results = packages.map((p) => {
      const r = { ecosystem: p.ecosystem, name: p.name, version: p.version };
      if (p.name === "tensorlake") r.malicious = [{ id: "MAL-2026-17650", versions: ["0.5.144"], matches_version: true }];
      if (p.name === "agent-vx") r.malicious = [{ id: "MAL-2026-17755", versions: ["0.1.0"] }];
      if (p.name === "postmark-mcp") r.malicious = [{ id: "MAL-2025-47227", versions: "all" }];
      if (p.name === "lodash") r.osv = { malicious: [], vulnerabilities: ["GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw"] };
      return r;
    });
    return { ok: true, json: async () => ({ ok: true, osv: "ok", results }) };
  };
}

test("pull request diff: fails on malicious packages and MCP server, warns on advisories, notes remote server", async () => {
  const r0 = makeRepo();
  const seen = [];
  try {
    const env = { GITHUB_EVENT_PATH: r0.event, GITHUB_STEP_SUMMARY: r0.summary, GITHUB_OUTPUT: r0.output };
    const r = await run({ cwd: r0.dir, env, fetchImpl: fakeApi(seen), log: () => {} });
    assert.equal(r.result, "fail");
    assert.deepEqual(r.files.sort(), [".mcp.json", "package-lock.json", "package.json", "requirements.txt"], "unchanged .vscode/mcp.json is not rescanned");
    const names = r.packages.map((p) => `${p.name}@${p.version ?? "-"}`).sort();
    assert.deepEqual(names, ["agent-vx@0.1.0", "lodash@4.17.15", "postmark-mcp@-", "requests@2.32.3", "tensorlake@0.5.144"], "express is unchanged and not checked");
    assert.equal(r.counts.malicious, 3);
    assert.equal(r.counts.advisories, 1);
    assert.equal(seen.length, 1);
    assert.ok(!Object.keys(seen[0].headers).some((h) => /authorization|cookie/i.test(h)), "no credentials sent");
    const md = readFileSync(r0.summary, "utf8");
    assert.match(md, /KarmaDue guard: FAIL/);
    assert.match(md, /MCP server "postmark" \(npx\)/);
    assert.match(md, /Remote MCP server https:\/\/mcp\.example\.com\/mcp/);
    assert.match(readFileSync(r0.output, "utf8"), /result=fail\nmalicious=3\nadvisories=1/);
  } finally { rmSync(r0.dir, { recursive: true, force: true }); }
});

test("on-advisory=ignore (GitHub input env names) and API outage handling", async () => {
  const r0 = makeRepo();
  try {
    process.env["INPUT_ON-ADVISORY"] = "ignore";
    const env = { GITHUB_EVENT_PATH: r0.event };
    const r = await run({ cwd: r0.dir, env, fetchImpl: fakeApi([]), log: () => {} });
    assert.equal(r.counts.advisories, 0);
    delete process.env["INPUT_ON-ADVISORY"];
    const down = async () => { throw new Error("network down"); };
    const w = await run({ cwd: r0.dir, env, fetchImpl: down, log: () => {} });
    assert.equal(w.result, "warn");
    assert.match(w.markdown, /lookup failed/i);
    process.env["INPUT_FAIL-ON-ERROR"] = "true";
    const f = await run({ cwd: r0.dir, env, fetchImpl: down, log: () => {} });
    assert.equal(f.result, "fail");
  } finally { delete process.env["INPUT_FAIL-ON-ERROR"]; delete process.env["INPUT_ON-ADVISORY"]; rmSync(r0.dir, { recursive: true, force: true }); }
});

test("no base available: scans every dependency file", async () => {
  const r0 = makeRepo();
  try {
    const r = await run({ cwd: r0.dir, env: {}, fetchImpl: fakeApi([]), log: () => {} });
    assert.ok(r.files.includes(".vscode/mcp.json"));
    assert.ok(r.packages.some((p) => p.name === "express"));
  } finally { rmSync(r0.dir, { recursive: true, force: true }); }
});

test("live API (KD_LIVE=1): the same pull request against the real KarmaDue data", { skip: !process.env.KD_LIVE }, async () => {
  const r0 = makeRepo();
  try {
    const out = join(FX, "..", "..", "example-summary.md");
    const r = await run({ cwd: r0.dir, env: { GITHUB_EVENT_PATH: r0.event, GITHUB_STEP_SUMMARY: out + ".tmp" }, log: () => {} });
    const md = readFileSync(out + ".tmp", "utf8");
    writeFileSync(out, md); rmSync(out + ".tmp");
    assert.equal(r.result, "fail");
    assert.ok(r.findings.some((f) => f.kind === "malicious" && f.pkg.name === "tensorlake"), "tensorlake 0.5.144 has a malicious-code report");
    assert.ok(r.findings.some((f) => f.kind === "advisory" && f.pkg.name === "lodash"), "lodash 4.17.15 has advisories in OSV");
  } finally { rmSync(r0.dir, { recursive: true, force: true }); }
});
