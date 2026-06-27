import { dirname, join, sep } from "node:path";
import fs from "node:fs";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const SELF_DIR = dirname(fileURLToPath(import.meta.url));

const NATIVE_PACKAGES = new Set([
  "@appthreat/chennai-linux-amd64",
  "@appthreat/chennai-linux-arm64",
  "@appthreat/chennai-darwin-arm64",
  "@appthreat/chennai-windows-amd64",
  "@appthreat/chennai-linux-amd64-musl",
]);

export function getLinuxLibc() {
  if (process.platform !== "linux") return null;
  try {
    const report = process.report?.getReport();
    if (typeof report === "object" && report?.header) {
      if (report.header.glibcVersionRuntime) return "glibc";
    }
  } catch (_) {}
  try {
    if (fs.existsSync("/etc/alpine-release")) return "musl";
  } catch (_) {}
  try {
    const out = execSync("ldd --version", { stdio: ["ignore", "pipe", "ignore"] }).toString();
    if (out.includes("musl")) return "musl";
  } catch (_) {}
  return "glibc";
}

export function resolveChennaiProvider(opts = {}) {
  const platform = opts.platform || process.platform;
  const arch = opts.arch || process.arch;
  let libc = opts.libc;
  if (platform === "linux" && !libc) libc = getLinuxLibc();

  let preferredPkg = null;
  let kind = "jar";

  if (platform === "win32") {
    if (arch === "x64") {
      preferredPkg = "@appthreat/chennai-windows-amd64";
      kind = "native";
    } else {
      preferredPkg = "@appthreat/chennai-win32-arm64";
      kind = "jar";
    }
  } else if (platform === "darwin") {
    if (arch === "arm64") {
      preferredPkg = "@appthreat/chennai-darwin-arm64";
      kind = "native";
    } else {
      preferredPkg = "@appthreat/chennai-darwin-amd64";
      kind = "jar";
    }
  } else if (platform === "linux") {
    if (arch === "x64") {
      preferredPkg = libc === "musl"
        ? "@appthreat/chennai-linux-amd64-musl"
        : "@appthreat/chennai-linux-amd64";
      kind = "native";
    } else if (arch === "arm64") {
      preferredPkg = libc === "musl"
        ? "@appthreat/chennai-linux-arm64-musl"
        : "@appthreat/chennai-linux-arm64";
      kind = libc === "musl" ? "jar" : "native";
    }
  }

  if (!preferredPkg) {
    preferredPkg = "@appthreat/chennai-jar";
    kind = "jar";
  }

  return { preferredPkg, kind, platform, arch, libc };
}

function readSelfVersion() {
  try {
    return JSON.parse(fs.readFileSync(join(SELF_DIR, "package.json"), "utf8")).version;
  } catch (_) {
    return undefined;
  }
}

function staticGlobalRoots() {
  const roots = new Set();
  const env = process.env;
  if (env.GLOBAL_NODE_MODULES_PATH) roots.add(env.GLOBAL_NODE_MODULES_PATH);
  const prefix = env.npm_config_prefix || env.PREFIX;
  if (prefix) {
    roots.add(join(prefix, "lib", "node_modules"));
    roots.add(join(prefix, "node_modules"));
  }
  const launch = process.argv[1];
  if (launch) {
    const binDir = dirname(launch);
    roots.add(join(binDir, "..", "lib", "node_modules"));
    roots.add(join(binDir, "node_modules"));
  }
  try {
    const execDir = dirname(process.execPath);
    roots.add(join(execDir, "..", "lib", "node_modules"));
    roots.add(join(execDir, "node_modules"));
  } catch (_) {}
  return [...roots];
}

let _queriedGlobalRoots;
function queriedGlobalRoots() {
  if (_queriedGlobalRoots) return _queriedGlobalRoots;
  const roots = new Set();
  for (const cmd of ["npm root -g", "pnpm root -g"]) {
    try {
      const out = execSync(cmd, { stdio: ["ignore", "pipe", "ignore"], encoding: "utf8" }).trim();
      if (out) roots.add(out);
    } catch (_) {}
  }
  _queriedGlobalRoots = [...roots];
  return _queriedGlobalRoots;
}

function candidatePackageDirs(pkgName, searchOpts = {}) {
  const folder = pkgName.split("/")[1];
  const version = readSelfVersion();
  const parts = SELF_DIR.split(sep);
  const dirs = [];

  dirs.push(join(SELF_DIR, "node_modules", "@appthreat", folder));

  for (let i = parts.length - 1; i >= 0; i--) {
    if (parts[i] === "node_modules") {
      const root = parts.slice(0, i + 1).join(sep) || sep;
      dirs.push(join(root, "@appthreat", folder));
      if (version) {
        dirs.push(join(root, ".pnpm", `@appthreat+${folder}@${version}`, "node_modules", "@appthreat", folder));
      }
    }
  }

  const pnpmMarker = `${sep}.pnpm${sep}`;
  const pnpmIdx = SELF_DIR.indexOf(pnpmMarker);
  if (pnpmIdx !== -1 && version) {
    const base = SELF_DIR.slice(0, pnpmIdx);
    dirs.push(join(base, ".pnpm", `@appthreat+${folder}@${version}`, "node_modules", "@appthreat", folder));
  }

  const globalRoots = staticGlobalRoots();
  if (searchOpts.includeQueriedGlobals) globalRoots.push(...queriedGlobalRoots());
  for (const root of globalRoots) {
    dirs.push(join(root, "@appthreat", folder));
    if (version) {
      dirs.push(join(root, ".pnpm", `@appthreat+${folder}@${version}`, "node_modules", "@appthreat", folder));
    }
  }

  return [...new Set(dirs)];
}

export function describeChennaiSearch(opts = {}) {
  const { preferredPkg, platform, arch, libc } = resolveChennaiProvider(opts);
  const packagesToTry = [preferredPkg];
  if (preferredPkg !== "@appthreat/chennai-jar") {
    packagesToTry.push("@appthreat/chennai-jar");
  }
  const attempts = [];
  for (const pkg of packagesToTry) {
    const isNative = NATIVE_PACKAGES.has(pkg);
    for (const pkgDir of candidatePackageDirs(pkg, { includeQueriedGlobals: true })) {
      const checkPath = isNative
        ? join(pkgDir, "bin", platform === "win32" ? "chennai.exe" : "chennai")
        : join(pkgDir, "plugins");
      attempts.push({ pkg, kind: isNative ? "native" : "jar", path: checkPath, exists: fs.existsSync(checkPath) });
    }
  }
  return { selfDir: SELF_DIR, platform, arch, libc, preferredPkg, attempts };
}

export function locateChennaiBinary(opts = {}) {
  const debug = !!process.env.CHENNAI_DEBUG;
  const { preferredPkg, platform } = resolveChennaiProvider(opts);

  if (debug) {
    console.error(`[chennai] resolver self dir: ${SELF_DIR}`);
    console.error(`[chennai] platform=${platform} preferred=${preferredPkg}`);
  }

  const packagesToTry = [preferredPkg];
  if (preferredPkg !== "@appthreat/chennai-jar") {
    packagesToTry.push("@appthreat/chennai-jar");
  }

  const tryPackage = (pkg, pkgDir) => {
    const isNative = NATIVE_PACKAGES.has(pkg);
    const exeName = platform === "win32" ? "chennai.exe" : "chennai";
    const binaryPath = join(pkgDir, "bin", exeName);
    if (debug) console.error(`[chennai] check ${binaryPath} -> ${fs.existsSync(binaryPath)}`);
    if (fs.existsSync(binaryPath)) {
      const engineName = platform === "win32" ? "chennai-engine.exe" : "chennai-engine";
      let enginePath = null;
      if (isNative) {
        enginePath = join(pkgDir, "bin", engineName);
        enginePath = fs.existsSync(enginePath) ? enginePath : null;
      } else {
        // JAR fallback: engine launcher lives under plugins/bin/
        const jarEnginePath = join(pkgDir, "plugins", "bin", engineName);
        enginePath = fs.existsSync(jarEnginePath) ? jarEnginePath : null;
      }
      return { kind: isNative ? "native" : "jar", pkg, binPath: binaryPath, enginePath, pkgDir };
    }
    return null;
  };

  for (const includeQueriedGlobals of [false, true]) {
    for (const pkg of packagesToTry) {
      for (const pkgDir of candidatePackageDirs(pkg, { includeQueriedGlobals })) {
        const found = tryPackage(pkg, pkgDir);
        if (found) return found;
      }
    }
  }
  return null;
}
