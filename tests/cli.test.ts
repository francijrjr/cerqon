import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true }))); });

const cli = path.resolve("apps/cli/dist/index.js");
function run(...args: string[]) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

describe("CLI exit policy", () => {
  it("reports a friendly missing target error with exit 2", { timeout: 20_000 }, () => {
    const result = run("scan", "does-not-exist", "--json");
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("CERQON_SCAN_TARGET_NOT_FOUND");
    expect(result.stderr).not.toContain("at Scanner");
    expect(result.stdout).toBe("");
  });
  it.each([["scan", ".", "--fail-on", "low"], ["scan", "--unknown"], ["unknown-command"]])("returns usage exit 2 for invalid arguments %j", (...args) => {
    expect(run(...args).status).toBe(2);
  });
  it.each(["rules", "doctor"])("runs %s successfully", (command) => {
    expect(run(command).status).toBe(0);
  });
  it("returns exit 3 if the report cannot be written", () => {
    const result = run("scan", "examples/secure-agent", "--json", "--output", "examples/secure-agent");
    expect(result.status).toBe(3);
    expect(result.stderr).toContain("CERQON_INTERNAL_SCANNER_ERROR");
  });
  it("returns a machine-readable failed scan for malformed JSON", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "cerqon-cli-")); dirs.push(dir);
    const file = path.join(dir, "broken.json");
    await fs.writeFile(file, '{"token":"ghp_abcdefghijklmnopqrstuvwxyz"');
    const result = run("scan", file, "--json");
    expect(result.status).toBe(2);
    const report = JSON.parse(result.stdout);
    expect(report.scanStatus).toBe("failed");
    expect(report.score).toBeNull();
    expect(report.diagnostics[0].code).toBe("CERQON_INVALID_JSON");
    expect(result.stdout + result.stderr).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz");
  });
  it("fails on high-only findings only when requested", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "cerqon-cli-")); dirs.push(dir);
    const file = path.join(dir, "high.json");
    await fs.writeFile(file, JSON.stringify({ mcpServers: { shell: { command: "bash" } } }));
    expect(run("scan", file, "--json", "--fail-on", "critical").status).toBe(0);
    expect(run("scan", file, "--json", "--fail-on", "high").status).toBe(1);
  });
  it.each(["critical", "high"])("enforces %s in JSON mode", (severity) => {
    const result = run("scan", "examples/insecure-agent", "--json", "--fail-on", severity);
    expect(result.status).toBe(1);
    expect(JSON.parse(result.stdout).findings.length).toBeGreaterThan(0);
  });
  it("does not fail an interactive scan by default", () => {
    expect(run("scan", "examples/insecure-agent").status).toBe(0);
  });
  it("passes a secure scan with an explicit threshold", () => {
    const result = run("scan", "examples/secure-agent", "--json", "--fail-on", "critical");
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout).score).toBe(100);
    const report = JSON.parse(result.stdout);
    expect(report.schemaVersion).toBe("1");
    expect(report.scanStatus).toBe("complete");
    expect(report.diagnostics).toEqual([]);
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });
});
