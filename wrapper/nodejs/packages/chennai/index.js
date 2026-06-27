#!/usr/bin/env node

import { platform as _platform } from "node:os";
import { dirname, join } from "node:path";
import { readFileSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { locateChennaiBinary, describeChennaiSearch } from "./resolve.js";

const isWin = _platform() === "win32";
const dirName = dirname(fileURLToPath(import.meta.url));
const selfPJson = JSON.parse(readFileSync(join(dirName, "package.json"), "utf8"));

export const CHENNAI_VERSION = selfPJson.version;

const provider = locateChennaiBinary();

export const executeChennai = (chennaiArgs) => {
  if (!provider) {
    console.error("Error: The '@appthreat/chennai' package was not installed correctly or is unsupported on this platform.");
    console.error("Please verify your installation and make sure optional dependencies are not blocked.");
    try {
      const diag = describeChennaiSearch();
      console.error(
        `\n[chennai] resolution diagnostics:\n` +
        `  dispatcher dir: ${diag.selfDir}\n` +
        `  platform=${diag.platform} arch=${diag.arch} libc=${diag.libc}\n` +
        `  preferred package: ${diag.preferredPkg}\n` +
        `  paths checked (${diag.attempts.length}):`
      );
      for (const a of diag.attempts) {
        console.error(`    [${a.exists ? "found" : "missing"}] (${a.pkg}, ${a.kind}) ${a.path}`);
      }
    } catch (e) {
      console.error(`[chennai] failed to produce diagnostics: ${e?.message || e}`);
    }
    process.exit(1);
  }

  const cwd = process.env.CHENNAI_CWD || process.cwd();
  const timeout = process.env.CHENNAI_TIMEOUT ? parseInt(process.env.CHENNAI_TIMEOUT, 10) : undefined;

  const env = { ...process.env };
  if (provider.enginePath) {
    env.CHENNAI_ENGINE = provider.enginePath;
  }

  const result = spawnSync(provider.binPath, chennaiArgs, {
    encoding: "utf-8",
    env,
    cwd,
    stdio: "inherit",
    timeout,
  });
  process.exit(result.status !== null ? result.status : 1);
};

if (process.argv[1]) {
  const argv = process.argv.slice(2);
  executeChennai(argv);
}
