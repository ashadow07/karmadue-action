// Dependency and MCP config parsers. No dependencies; each returns [{ ecosystem, name, version, spec }] (version is exact or null).
const NPM = "npm";
const PYPI = "PyPI";

export const pyNorm = (n) => String(n).trim().toLowerCase().replace(/[-_.]+/g, "-");
const exactNpm = (spec) => {
  const s = String(spec ?? "").trim().replace(/^npm:(?:@?[^@]+)@/, "").replace(/^[=v]+/, "");
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/.test(s) ? s : null;
};

export function parsePackageJson(text) {
  const j = safeJson(text);
  if (!j || typeof j !== "object") return [];
  const out = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const [name, spec] of Object.entries(j[field] ?? {})) {
      if (typeof spec !== "string" || /^(file|link|workspace|git|github|https?):/.test(spec) || spec.includes("/") && !spec.startsWith("npm:")) continue;
      out.push({ ecosystem: NPM, name, version: exactNpm(spec), spec });
    }
  }
  return out;
}

export function parsePackageLock(text) {
  const j = safeJson(text);
  if (!j) return [];
  const out = [];
  if (j.packages && typeof j.packages === "object") {
    for (const [path, info] of Object.entries(j.packages)) {
      if (!path || !info || typeof info.version !== "string" || info.link) continue;
      const name = info.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      if (name) out.push({ ecosystem: NPM, name, version: info.version, spec: info.version });
    }
    return out;
  }
  const walk = (deps) => {
    for (const [name, info] of Object.entries(deps ?? {})) {
      if (info && typeof info.version === "string" && !/^(file|link|git)/.test(info.version)) out.push({ ecosystem: NPM, name, version: info.version, spec: info.version });
      if (info?.dependencies) walk(info.dependencies);
    }
  };
  walk(j.dependencies);
  return out;
}

export function parseYarnLock(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  let names = [];
  for (const line of lines) {
    if (/^\S/.test(line) && line.trim().endsWith(":") && !line.startsWith("#") && !line.startsWith("__metadata")) {
      names = line.slice(0, -1).split(",").map((s) => s.trim().replace(/^"|"$/g, "")).map((s) => {
        const at = s.lastIndexOf("@");
        return at > 0 ? s.slice(0, at) : s;
      }).filter(Boolean);
      names = [...new Set(names)];
      continue;
    }
    const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?\s*$/);
    if (m && names.length) {
      for (const n of names) out.push({ ecosystem: NPM, name: n, version: m[1], spec: m[1] });
      names = [];
    }
  }
  return out;
}

export function parsePnpmLock(text) {
  const out = [];
  let inPkgs = false;
  for (const line of String(text).split(/\r?\n/)) {
    if (/^(packages|snapshots):\s*$/.test(line)) { inPkgs = line.startsWith("packages"); continue; }
    if (/^\S/.test(line)) inPkgs = false;
    if (!inPkgs) continue;
    const m = line.match(/^ {2}['"]?\/?((?:@[^/@\s]+\/)?[^/@\s'"(]+)[@/](\d[^:'"()\s]*)/);
    if (m) out.push({ ecosystem: NPM, name: m[1], version: m[2], spec: m[2] });
  }
  return out;
}

function reqLine(line) {
  const s = line.replace(/\s+#.*$/, "").trim();
  if (!s || s.startsWith("#") || s.startsWith("-") || /^[a-z]+\+|:\/\//i.test(s)) return null;
  const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
  if (!m) return null;
  const spec = m[3].split(";")[0].trim();
  const pin = spec.match(/^===?\s*([A-Za-z0-9.!+_-]+)$/);
  return { ecosystem: PYPI, name: m[1], version: pin ? pin[1] : null, spec };
}

export function parseRequirements(text) {
  return String(text).split(/\r?\n/).map(reqLine).filter(Boolean);
}

// Minimal TOML reading: [project] dependencies = [...] and [tool.poetry.*dependencies] tables.
export function parsePyproject(text) {
  const out = [];
  const src = String(text);
  const proj = src.match(/^\[project\][\s\S]*?^dependencies\s*=\s*\[([\s\S]*?)\]/m);
  if (proj) for (const m of proj[1].matchAll(/["']([^"']+)["']/g)) { const r = reqLine(m[1]); if (r) out.push(r); }
  const opt = src.match(/^\[project\.optional-dependencies\]([\s\S]*?)(?=^\[)/m);
  if (opt) for (const m of opt[1].matchAll(/["']([^"']+)["']/g)) { const r = reqLine(m[1]); if (r) out.push(r); }
  let section = "";
  for (const line of src.split(/\r?\n/)) {
    const h = line.match(/^\[([^\]]+)\]\s*$/);
    if (h) { section = h[1]; continue; }
    if (!/^tool\.poetry(\.group\.[^.]+)?\.(dev-)?dependencies$/.test(section)) continue;
    const m = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/);
    if (!m || m[1].toLowerCase() === "python") continue;
    const v = m[2].trim();
    const str = v.match(/^["']([^"']*)["']/) ?? v.match(/version\s*=\s*["']([^"']*)["']/);
    const spec = str ? str[1] : v;
    const pin = spec.match(/^(?:==)?\s*(\d[A-Za-z0-9.!+_-]*)$/);
    out.push({ ecosystem: PYPI, name: m[1], version: pin ? pin[1] : null, spec });
  }
  return out;
}

// poetry.lock and uv.lock share [[package]] name = "..." version = "...".
export function parseTomlLock(text) {
  const out = [];
  for (const block of String(text).split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    const source = block.match(/^source\s*=\s*\{([^}]*)\}/m)?.[1] ?? "";
    if (name && version && !/(editable|virtual|directory|path)\s*=/.test(source)) out.push({ ecosystem: PYPI, name, version, spec: version });
  }
  return out;
}

export function parsePipfileLock(text) {
  const j = safeJson(text);
  const out = [];
  for (const sec of ["default", "develop"]) for (const [name, info] of Object.entries(j?.[sec] ?? {})) {
    const v = typeof info?.version === "string" ? info.version.replace(/^==/, "") : null;
    out.push({ ecosystem: PYPI, name, version: v, spec: info?.version ?? "" });
  }
  return out;
}

// ---- MCP configs ----------------------------------------------------------------------------------------------------------------
export function stripJsonc(text) {
  let out = "", i = 0, str = false;
  const s = String(text);
  while (i < s.length) {
    const c = s[i], n = s[i + 1];
    if (str) { out += c; if (c === "\\") { out += n ?? ""; i += 2; continue; } if (c === '"') str = false; i++; continue; }
    if (c === '"') { str = true; out += c; i++; continue; }
    if (c === "/" && n === "/") { while (i < s.length && s[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function safeJson(text) {
  if (!text || !String(text).trim()) return null;
  try { return JSON.parse(text); } catch { try { return JSON.parse(stripJsonc(text)); } catch { return null; } }
}

export function parseMcpConfig(text) {
  const j = safeJson(text);
  const servers = j?.mcpServers ?? j?.servers ?? j?.mcp?.servers ?? {};
  const out = [];
  if (!servers || typeof servers !== "object") return out;
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== "object") continue;
    const url = cfg.url ?? cfg.serverUrl ?? null;
    const command = typeof cfg.command === "string" ? cfg.command : null;
    const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
    out.push({ name, command, args, url, identity: JSON.stringify({ command, args, url }), launch: command ? launchPackage(command, args) : null });
  }
  return out;
}

const NPX_VALUE_FLAGS = new Set(["-p", "--package", "--registry", "--cache", "--userconfig", "-c", "--call", "--node-options"]);
const UVX_VALUE_FLAGS = new Set(["--from", "--with", "-w", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--default-index", "--with-requirements", "--constraint", "-c"]);

function npmSpec(spec) {
  const s = String(spec).replace(/^npm:/, "");
  const at = s.lastIndexOf("@");
  if (at > 0) return { name: s.slice(0, at), version: s.slice(at + 1) || null };
  return { name: s, version: null };
}
function pySpec(spec) {
  const s = String(spec).replace(/\[[^\]]*\]/, "");
  const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:(?:==|@)\s*([A-Za-z0-9.!+_-]+))?/);
  return m ? { name: m[1], version: m[2] ?? null } : null;
}

/** What package an MCP launch command runs: { ecosystem, name, version, runner } or { docker } or null. */
export function launchPackage(command, args) {
  let parts = [command, ...(args ?? [])].map(String);
  const base = (p) => p.split(/[\\/]/).pop().toLowerCase().replace(/\.(cmd|exe|bat)$/, "");
  if (base(parts[0]) === "cmd" && /^\/c$/i.test(parts[1] ?? "")) parts = parts.slice(2);
  if (!parts.length) return null;
  let cmd = base(parts[0]);
  let rest = parts.slice(1);
  if ((cmd === "pnpm" || cmd === "yarn") && rest[0] === "dlx") { cmd = "npx"; rest = rest.slice(1); }
  if (cmd === "npm" && (rest[0] === "exec" || rest[0] === "x")) { cmd = "npx"; rest = rest.slice(1); }
  if (cmd === "bunx" || (cmd === "bun" && rest[0] === "x")) { if (cmd === "bun") rest = rest.slice(1); cmd = "npx"; }
  if (cmd === "uv" && rest[0] === "tool" && rest[1] === "run") { cmd = "uvx"; rest = rest.slice(2); }
  if (cmd === "pipx" && rest[0] === "run") { cmd = "uvx"; rest = rest.slice(1); }
  if (cmd === "npx") {
    let pkgFlag = null;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === "--") { const s = rest[i + 1]; return s ? { ecosystem: NPM, ...npmSpec(pkgFlag ?? s), runner: "npx" } : null; }
      if (a.startsWith("--package=")) { pkgFlag = a.slice(10); continue; }
      if (NPX_VALUE_FLAGS.has(a)) { if (a === "-p" || a === "--package") pkgFlag = rest[i + 1]; i++; continue; }
      if (a.startsWith("-")) continue;
      return { ecosystem: NPM, ...npmSpec(pkgFlag ?? a), runner: "npx" };
    }
    return null;
  }
  if (cmd === "uvx") {
    let from = null;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a.startsWith("--from=")) { from = a.slice(7); continue; }
      if (UVX_VALUE_FLAGS.has(a)) { if (a === "--from") from = rest[i + 1]; i++; continue; }
      if (a.startsWith("-")) continue;
      const p = pySpec(from ?? a);
      return p ? { ecosystem: PYPI, ...p, runner: "uvx" } : null;
    }
    return null;
  }
  if (cmd === "docker" || cmd === "podman") {
    const i = rest.indexOf("run");
    if (i < 0) return null;
    for (let k = i + 1; k < rest.length; k++) {
      const a = rest[k];
      if (/^(-e|--env|-v|--volume|--name|--network|-p|--publish|--entrypoint|-w|--workdir|--env-file|-u|--user|--mount|--platform|--pull)$/.test(a)) { k++; continue; }
      if (a.startsWith("-")) continue;
      return { docker: a };
    }
  }
  return null;
}

// ---- file routing ---------------------------------------------------------------------------------------------------------------
export function fileKind(path) {
  const p = path.replace(/\\/g, "/");
  if (/(^|\/)node_modules\//.test(p)) return null;
  const b = p.split("/").pop();
  if (b === "package.json") return "package.json";
  if (b === "package-lock.json" || b === "npm-shrinkwrap.json") return "package-lock";
  if (b === "yarn.lock") return "yarn.lock";
  if (b === "pnpm-lock.yaml") return "pnpm-lock";
  if (/^requirements.*\.(txt|in)$/i.test(b) || /(^|\/)requirements\/[^/]+\.(txt|in)$/i.test(p)) return "requirements";
  if (b === "pyproject.toml") return "pyproject";
  if (b === "poetry.lock" || b === "uv.lock") return "toml-lock";
  if (b === "Pipfile.lock") return "pipfile-lock";
  if (/(^|\/)\.mcp\.json$/.test(p) || /(^|\/)\.cursor\/mcp\.json$/.test(p) || /(^|\/)\.vscode\/mcp\.json$/.test(p)) return "mcp";
  return null;
}

export function parseFile(kind, text) {
  switch (kind) {
    case "package.json": return parsePackageJson(text);
    case "package-lock": return parsePackageLock(text);
    case "yarn.lock": return parseYarnLock(text);
    case "pnpm-lock": return parsePnpmLock(text);
    case "requirements": return parseRequirements(text);
    case "pyproject": return parsePyproject(text);
    case "toml-lock": return parseTomlLock(text);
    case "pipfile-lock": return parsePipfileLock(text);
    default: return [];
  }
}
