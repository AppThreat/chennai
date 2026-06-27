import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const packagesDir = path.join(rootDir, "packages");

if (!fs.existsSync(packagesDir)) {
  fs.mkdirSync(packagesDir, { recursive: true });
}

const parentPkgJson = JSON.parse(fs.readFileSync(path.join(packagesDir, "chennai", "package.json"), "utf8"));
const version = parentPkgJson.version;

const rootLicense = path.resolve(__dirname, "..", "..", "..", "LICENSE");
const licenseContent = fs.readFileSync(rootLicense, "utf8");

const packagesInfo = [
  {
    name: "@appthreat/chennai-jar",
    kind: "jar",
    description: "Universal JAR fallback package for @appthreat/chennai",
  },
  {
    name: "@appthreat/chennai-linux-amd64",
    kind: "native",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["glibc"],
    description: "Linux x64 (glibc) native binary for @appthreat/chennai",
  },
  {
    name: "@appthreat/chennai-linux-arm64",
    kind: "native",
    os: ["linux"],
    cpu: ["arm64"],
    libc: ["glibc"],
    description: "Linux arm64 (glibc) native binary for @appthreat/chennai",
  },
  {
    name: "@appthreat/chennai-linux-amd64-musl",
    kind: "native",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["musl"],
    description: "Linux x64 (musl) native binary for @appthreat/chennai",
  },
  {
    name: "@appthreat/chennai-darwin-arm64",
    kind: "native",
    os: ["darwin"],
    cpu: ["arm64"],
    description: "Darwin arm64 native binary for @appthreat/chennai",
  },
  {
    name: "@appthreat/chennai-windows-amd64",
    kind: "native",
    os: ["win32"],
    cpu: ["x64"],
    description: "Windows x64 native binary for @appthreat/chennai",
  },
];

function stageParentMetadata() {
  const chennaiDir = path.join(packagesDir, "chennai");
  fs.writeFileSync(path.join(chennaiDir, "LICENSE"), licenseContent, "utf8");
  // Copy the root README so the npm package ships the full documentation
  const rootReadme = path.resolve(__dirname, "..", "..", "..", "README.md");
  const readmeDest = path.join(chennaiDir, "README.md");
  if (fs.existsSync(rootReadme)) {
    fs.copyFileSync(rootReadme, readmeDest);
  } else {
    fs.writeFileSync(readmeDest, "# @appthreat/chennai\n\nInteractive terminal UI for exploring AppThreat atom files with AI agent.\n", "utf8");
  }
}

const targetPkgName = process.argv[2];
const srcTuiArg = process.argv[3];
const srcEngineArg = process.argv[4];

stageParentMetadata();

const selectedPkgs = targetPkgName
  ? packagesInfo.filter((p) => p.name === targetPkgName)
  : packagesInfo;

if (targetPkgName && selectedPkgs.length === 0) {
  console.error(`Error: Unknown sub-package name "${targetPkgName}"`);
  process.exit(1);
}

for (const pkg of selectedPkgs) {
  const folderName = pkg.name.split("/")[1];
  const pkgDir = path.join(packagesDir, folderName);

  if (!fs.existsSync(pkgDir)) {
    fs.mkdirSync(pkgDir, { recursive: true });
  }

  const subPkgJson = {
    name: pkg.name,
    version,
    description: pkg.description,
    repository: {
      type: "git",
      url: "git+https://github.com/AppThreat/chennai.git",
    },
    author: "Team AppThreat <cloud@appthreat.com>",
    license: "MIT",
    bugs: {
      url: "https://github.com/AppThreat/chennai/issues",
    },
    homepage: "https://github.com/AppThreat/chennai#readme",
  };

  if (pkg.os) subPkgJson.os = pkg.os;
  if (pkg.cpu) subPkgJson.cpu = pkg.cpu;
  if (pkg.libc) subPkgJson.libc = pkg.libc;

  if (pkg.kind === "native") {
    subPkgJson.files = ["bin/"];
  } else {
    subPkgJson.files = ["bin/", "plugins/"];
  }

  fs.writeFileSync(path.join(pkgDir, "package.json"), JSON.stringify(subPkgJson, null, 2), "utf8");
  fs.writeFileSync(path.join(pkgDir, "LICENSE"), licenseContent, "utf8");

  const readmeContent = `# ${pkg.name}\n\n${pkg.description}.\n\nThis is an internal package used by \`@appthreat/chennai\` and is not intended to be installed directly.\n`;
  fs.writeFileSync(path.join(pkgDir, "README.md"), readmeContent, "utf8");

  if (srcTuiArg) {
    const binDir = path.join(pkgDir, "bin");
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }
    const isWinPkg = pkg.os && pkg.os.includes("win32");
    const destTuiName = isWinPkg ? "chennai.exe" : "chennai";
    const destTuiPath = path.join(binDir, destTuiName);

    console.log(`Copying TUI binary from ${srcTuiArg} to ${destTuiPath}`);
    fs.copyFileSync(srcTuiArg, destTuiPath);
    fs.chmodSync(destTuiPath, 0o755);

    if (fs.statSync(destTuiPath).size === 0) {
      console.error(`Error: copied TUI binary ${destTuiPath} is empty`);
      process.exit(1);
    }
  }

  if (srcEngineArg && pkg.kind === "native") {
    const binDir = path.join(pkgDir, "bin");
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }
    const isWinPkg = pkg.os && pkg.os.includes("win32");
    const destEngineName = isWinPkg ? "chennai-engine.exe" : "chennai-engine";
    const destEnginePath = path.join(binDir, destEngineName);

    console.log(`Copying engine binary from ${srcEngineArg} to ${destEnginePath}`);
    fs.copyFileSync(srcEngineArg, destEnginePath);
    fs.chmodSync(destEnginePath, 0o755);

    if (fs.statSync(destEnginePath).size === 0) {
      console.error(`Error: copied engine binary ${destEnginePath} is empty`);
      process.exit(1);
    }
  }

  if (srcEngineArg && pkg.kind === "jar") {
    const pluginDir = path.join(pkgDir, "plugins");
    if (fs.existsSync(pluginDir)) {
      fs.rmSync(pluginDir, { recursive: true, force: true });
    }
    console.log(`Copying engine plugins from ${srcEngineArg} to ${pluginDir}`);
    const copyDirSync = (src, dest) => {
      fs.mkdirSync(dest, { recursive: true });
      const entries = fs.readdirSync(src, { withFileTypes: true });
      for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
          copyDirSync(srcPath, destPath);
        } else {
          fs.copyFileSync(srcPath, destPath);
        }
      }
    };
    copyDirSync(srcEngineArg, pluginDir);
  }
}

console.log("Assembly completed successfully.");
