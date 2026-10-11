import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../src/parsers.mjs";

const fx = (n) => readFileSync(new URL(`./fixtures/formats/${n}`, import.meta.url), "utf8");
const pairs = (list) => list.map((p) => `${p.name}@${p.version ?? "-"}`).sort();

test("package-lock v3 and v1", () => {
  assert.deepEqual(pairs(P.parsePackageLock(fx("package-lock.v3.json"))), ["@scope/tool@1.0.0", "debug@2.6.9", "express@4.18.2"]);
  assert.deepEqual(pairs(P.parsePackageLock(fx("package-lock.v1.json"))), ["left-pad@1.3.0", "nested@0.1.0"]);
});

test("yarn classic and berry", () => {
  assert.deepEqual(pairs(P.parseYarnLock(fx("yarn.v1.lock"))), ["@babel/core@7.24.0", "lodash@4.17.15"]);
  assert.deepEqual(pairs(P.parseYarnLock(fx("yarn.berry.lock"))), ["lodash@4.17.21"]);
});

test("pnpm v9 and v6", () => {
  assert.deepEqual(pairs(P.parsePnpmLock(fx("pnpm-lock.v9.yaml"))), ["@modelcontextprotocol/sdk@1.20.0", "zod@3.23.8"]);
  assert.deepEqual(pairs(P.parsePnpmLock(fx("pnpm-lock.v6.yaml"))), ["@types/node@20.11.0", "ms@2.1.3"]);
});

test("requirements: pins, ranges, extras, markers; skips flags and VCS lines", () => {
  assert.deepEqual(pairs(P.parseRequirements(fx("requirements.txt"))), ["Flask@-", "agent_vx@0.1.0", "requests@2.19.0", "uvicorn@0.30.1"]);
});

test("pyproject: PEP 621 and Poetry tables", () => {
  assert.deepEqual(pairs(P.parsePyproject(fx("pyproject.toml"))), ["black@24.4.2", "fastapi@0.110.0", "httpx@0.27.0", "pydantic@-", "pytest@8.2.0", "rich@-"]);
});

test("poetry.lock, uv.lock (skips the editable project), Pipfile.lock", () => {
  assert.deepEqual(pairs(P.parseTomlLock(fx("poetry.lock"))), ["Jinja2@3.1.3", "certifi@2024.2.2"]);
  assert.deepEqual(pairs(P.parseTomlLock(fx("uv.lock"))), ["anyio@4.4.0"]);
  assert.deepEqual(pairs(P.parsePipfileLock(fx("Pipfile.lock"))), ["pytest@8.0.0", "six@1.16.0"]);
});

test("package.json: exact pins get a version, ranges and non-registry specs don't", () => {
  const list = P.parsePackageJson(JSON.stringify({ dependencies: { a: "1.2.3", b: "^1.0.0", c: "file:../c", d: "github:x/d", e: "npm:real@2.0.0" }, devDependencies: { f: "=3.0.0" } }));
  assert.deepEqual(pairs(list), ["a@1.2.3", "b@-", "e@2.0.0", "f@3.0.0"]);
});

test("MCP configs: VS Code JSONC, Cursor/Claude mcpServers", () => {
  const vs = P.parseMcpConfig(fx("mcp.vscode.jsonc"));
  assert.equal(vs.length, 2);
  assert.deepEqual(vs[0].launch, { ecosystem: "npm", name: "@modelcontextprotocol/server-filesystem", version: "2025.8.21", runner: "npx" });
  assert.equal(vs[1].url, "https://mcp.example.com/mcp");
  const cur = Object.fromEntries(P.parseMcpConfig(fx("mcp.cursor.json")).map((s) => [s.name, s.launch]));
  assert.deepEqual(cur.py, { ecosystem: "PyPI", name: "mcp-server-fetch", version: "2025.4.7", runner: "uvx" });
  assert.deepEqual(cur.win, { ecosystem: "npm", name: "postmark-mcp", version: null, runner: "npx" });
  assert.deepEqual(cur.docker, { docker: "ghcr.io/github/github-mcp-server" });
  assert.equal(cur.local, null);
});

test("launch forms: pnpm dlx, bunx, npm exec, pipx run, uv tool run, --package", () => {
  assert.equal(P.launchPackage("pnpm", ["dlx", "foo@1.0.0"]).name, "foo");
  assert.equal(P.launchPackage("bunx", ["bar"]).name, "bar");
  assert.equal(P.launchPackage("npm", ["exec", "--yes", "--", "baz@2.0.0"]).version, "2.0.0");
  assert.equal(P.launchPackage("npx", ["--package=@s/real", "bin-name"]).name, "@s/real");
  assert.deepEqual(P.launchPackage("pipx", ["run", "qux==1.1"]), { ecosystem: "PyPI", name: "qux", version: "1.1", runner: "uvx" });
  assert.equal(P.launchPackage("uv", ["tool", "run", "--python", "3.12", "zap"]).name, "zap");
  assert.equal(P.launchPackage("C:\\Program Files\\nodejs\\npx.cmd", ["-y", "w"]).name, "w");
});

test("fileKind routes only the files the action scans", () => {
  const k = (p) => P.fileKind(p);
  assert.equal(k("package.json"), "package.json");
  assert.equal(k("web/package-lock.json"), "package-lock");
  assert.equal(k("node_modules/x/package.json"), null);
  assert.equal(k("requirements-dev.txt"), "requirements");
  assert.equal(k("requirements/base.txt"), "requirements");
  assert.equal(k(".cursor/mcp.json"), "mcp");
  assert.equal(k(".vscode/mcp.json"), "mcp");
  assert.equal(k("sub/.mcp.json"), "mcp");
  assert.equal(k("mcp.json"), null);
  assert.equal(k("uv.lock"), "toml-lock");
});
