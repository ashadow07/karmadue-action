import test from "node:test";
import assert from "node:assert/strict";
import { diffFile, evaluate, judge, mergePackages, serverPackages, summaryMarkdown, lookup } from "../src/core.mjs";

const cfg = { onAdvisory: "warn", onChange: "warn" };

test("diff: only added or changed versions; MCP servers by identity", () => {
  const before = JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/a": { version: "1.0.0" }, "node_modules/b": { version: "1.0.0" } } });
  const after = JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/a": { version: "1.0.0" }, "node_modules/b": { version: "1.1.0" }, "node_modules/c": { version: "2.0.0" } } });
  const d = diffFile("package-lock.json", before, after);
  assert.deepEqual(d.packages.map((p) => `${p.name}@${p.version}:${p.change}:${p.from}`), ["b@1.1.0:updated:1.0.0", "c@2.0.0:added:null"]);
  const m = diffFile(".mcp.json", JSON.stringify({ mcpServers: { x: { command: "npx", args: ["x"] }, y: { command: "npx", args: ["y"] } } }),
    JSON.stringify({ mcpServers: { x: { command: "npx", args: ["x"] }, y: { command: "npx", args: ["y@2.0.0"] }, z: { url: "https://z" } } }));
  assert.deepEqual(m.servers.map((s) => `${s.name}:${s.change}`), ["y:changed", "z:added"]);
  assert.equal(diffFile("README.md", "", "x").packages.length, 0);
  assert.equal(diffFile("package-lock.json", before, after, true).packages.length, 3, "scan all");
});

test("merge: lockfile version replaces a package.json range for the same package", () => {
  const out = mergePackages([
    { ecosystem: "npm", name: "a", version: null, spec: "^1", file: "package.json" },
    { ecosystem: "npm", name: "a", version: "1.2.0", file: "package-lock.json" },
    { ecosystem: "npm", name: "a", version: "1.2.0", file: "web/package-lock.json" },
    { ecosystem: "PyPI", name: "Foo_Bar", version: "1.0", file: "requirements.txt" },
    { ecosystem: "PyPI", name: "foo-bar", version: "1.0", file: "poetry.lock" },
  ]);
  assert.equal(out.length, 2);
  assert.deepEqual(out[0].files, ["package-lock.json", "web/package-lock.json"]);
  assert.deepEqual(out[1].files, ["requirements.txt", "poetry.lock"]);
});

test("judge: malicious all versions fails; pinned report on another version does not", () => {
  const pkg = { ecosystem: "npm", name: "evil", version: "2.0.0", files: ["package-lock.json"] };
  assert.equal(judge(pkg, { malicious: [{ id: "MAL-1", versions: "all" }] }, cfg)[0].level, "fail");
  assert.equal(judge(pkg, { malicious: [{ id: "MAL-1", versions: ["1.0.0"] }] }, cfg).length, 0);
  assert.equal(judge(pkg, { osv: { malicious: ["MAL-9"], vulnerabilities: [] } }, cfg)[0].kind, "malicious");
  const unpinned = judge({ ...pkg, version: null, spec: "unpinned" }, { malicious: [{ id: "MAL-1", versions: ["1.0.0"] }] }, cfg);
  assert.deepEqual(unpinned.map((f) => f.level), ["warn", "info"]);
});

test("judge: advisories warn by default, fail when configured, ignored when off; changes warn", () => {
  const pkg = { ecosystem: "npm", name: "lodash", version: "4.17.15", files: ["package-lock.json"] };
  const res = { vulnerabilities: [{ id: "GHSA-a", affects_version: true }, { id: "GHSA-b", affects_version: null }], osv: { malicious: [], vulnerabilities: ["GHSA-a", "GHSA-c"] } };
  const w = judge(pkg, res, cfg);
  assert.equal(w[0].level, "warn");
  assert.match(w[0].text, /2 published advisories/);
  assert.equal(judge(pkg, res, { ...cfg, onAdvisory: "fail" })[0].level, "fail");
  assert.equal(judge(pkg, res, { ...cfg, onAdvisory: "ignore" }).length, 0);
  const ch = judge(pkg, { catalog: [{ resource_id: "kd:res:github:x/y", passport: "https://p", changes_30d: [{ kind: "owner", detected_at: "2026-10-12T00:00:00Z", before: { owner: "a" }, after: { owner: "b" }, evidence: [{ url: "https://github.com/b/y" }] }] }] }, cfg);
  assert.equal(ch[0].kind, "changed");
  assert.deepEqual(ch[0].evidence, ["https://p", "https://github.com/b/y"]);
});

test("evaluate + summary: result, counts, notes for remote/docker servers", () => {
  const servers = [{ name: "docs", url: "https://x/mcp", command: null, args: [], file: ".mcp.json" }, { name: "d", command: "docker", args: [], launch: { docker: "img" }, file: ".mcp.json" }];
  const packages = [{ ecosystem: "npm", name: "evil", version: "1.0.0", files: ["package-lock.json"] }];
  const ev = evaluate(packages, servers, [{ malicious: [{ id: "MAL-1", versions: "all" }] }], cfg);
  assert.equal(ev.result, "fail");
  assert.deepEqual(ev.counts, { malicious: 1, advisories: 0, changes: 0, checked: 3 });
  const md = summaryMarkdown(ev, { scope: "changes", files: ["package-lock.json", ".mcp.json"], packageCount: 1, serverCount: 2, osv: "ok", calls: 1 });
  assert.match(md, /KarmaDue guard: FAIL/);
  assert.match(md, /\[1\]\(https:\/\/osv\.dev\/vulnerability\/MAL-1\)/);
  assert.match(md, /What this does not prove/);
  assert.match(md, /2 notes/);
  assert.equal(evaluate([], [], [], cfg).result, "pass");
});

test("serverPackages keeps exact versions only", () => {
  const s = serverPackages([{ name: "a", file: ".mcp.json", change: "added", launch: { ecosystem: "npm", name: "x", version: "latest", runner: "npx" } },
    { name: "b", file: ".mcp.json", change: "added", launch: { ecosystem: "PyPI", name: "y", version: "1.0", runner: "uvx" } }]);
  assert.deepEqual(s.map((p) => p.version), [null, "1.0"]);
});

test("lookup chunks at 500 and sends no token", async () => {
  const calls = [];
  const fake = async (url, init) => { calls.push({ url, init }); const body = JSON.parse(init.body); return { ok: true, json: async () => ({ osv: "ok", results: body.packages.map(() => ({})) }) }; };
  const pk = Array.from({ length: 1201 }, (_, i) => ({ ecosystem: "npm", name: `p${i}`, version: "1.0.0" }));
  const r = await lookup("https://api.test/v1/", pk, { fetchImpl: fake });
  assert.equal(r.length, 1201);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].url, "https://api.test/v1/packages/check");
  assert.ok(!("Authorization" in calls[0].init.headers));
});
