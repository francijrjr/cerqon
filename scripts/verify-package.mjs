import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const pnpm = process.env.npm_execpath;
assert(pnpm, "pnpm executable path is required");
const npmCli = path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
const temp = await mkdtemp(path.join(os.tmpdir(), "cerqon-pack-"));
function run(command, args, cwd = root, expected = 0) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", timeout: 180000 });
  assert.equal(result.status, expected, result.error?.message ?? result.stderr + result.stdout);
  return result.stdout;
}
try {
  run(process.execPath, [pnpm, "--filter", "@cerqon/cli", "pack", "--pack-destination", temp]);
  const tarball = path.join(temp, (await readdir(temp)).find((file) => file.endsWith(".tgz")));
  const entries = run("tar", ["-tf", tarball]).trim().split(/\r?\n/);
  const allowed = new Set(["package/package.json", "package/README.md", "package/LICENSE", "package/bin/cerqon.js", "package/dist/index.js"]);
  assert(entries.every((file) => allowed.has(file)), "Unexpected files in package: " + entries.join(", "));
  run(process.execPath, [npmCli, "install", "--ignore-scripts", "--no-package-lock", "--prefix", temp, tarball], root);
  const installed = path.join(temp, "node_modules/@cerqon/cli");
  const manifest = JSON.parse(await readFile(path.join(installed, "package.json"), "utf8"));
  assert(Object.entries(manifest.dependencies).every(([name, version]) => !name.startsWith("@cerqon/") && !version.includes("workspace:")));
  const cli = path.join(installed, "bin/cerqon.js");
  const report = JSON.parse(run(process.execPath, [cli, "scan", path.join(root, "examples/secure-agent"), "--json"], temp));
  assert.equal(report.score, 100);
  assert.equal(report.schemaVersion, "1");
  const unsafe = JSON.parse(run(process.execPath, [cli, "scan", path.join(root, "examples/insecure-agent"), "--json", "--fail-on", "critical"], temp, 1));
  assert(unsafe.summary.critical > 0);
  run(process.execPath, [cli, "doctor"], temp);
  console.log("Tarball contents verified:", entries.join(", "));
  console.log("Isolated installed CLI passed secure, threshold and doctor checks.");
} finally {
  assert(path.dirname(temp) === os.tmpdir() && path.basename(temp).startsWith("cerqon-pack-"));
  await rm(temp, { recursive: true, force: true });
}
