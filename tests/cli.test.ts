import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import path from "node:path";

const cli = path.resolve("apps/cli/dist/index.js");
function run(...args: string[]) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

describe("CLI exit policy", () => {
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
