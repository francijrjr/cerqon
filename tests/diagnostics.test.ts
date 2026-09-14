import { afterEach, expect, it, vi } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Scanner } from "@cerqon/scanner";
import { GenericMCPAdapter } from "@cerqon/adapters";
import { RiskEngine, cq002UnrestrictedFilesystem } from "@cerqon/risk-engine";
import type { ScanDiagnostic } from "@cerqon/types";

const dirs: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(dirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true }))); });
async function fixture(raw: string) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "cerqon-diagnostic-"));
  dirs.push(dir);
  await fs.writeFile(path.join(dir, "mcp.json"), raw);
  return dir;
}

it.each(['{"mcpServers":', '{"mcpServers": []}', '{"something": true}', '{"mcpServers":{"bad":{"command":42}}}']) ("never awards a clean score for invalid configuration: %s", async (raw) => {
  const result = await new Scanner().scan(await fixture(raw));
  expect(result.scanStatus).toBe("failed");
  expect(result.score).toBeNull();
  expect(result.findings).toEqual([]);
  expect(result.diagnostics[0].severity).toBe("error");
});

it("reports partial analysis when a sibling detected configuration is invalid", async () => {
  const dir = await fixture('{"mcpServers": {}}');
  await fs.writeFile(path.join(dir, "claude_desktop_config.json"), '{"token":"ghp_abcdefghijklmnopqrstuvwxyz"');
  const result = await new Scanner().scan(dir);
  expect(result.scanStatus).toBe("partial");
  expect(result.score).toBeNull();
  expect(JSON.stringify(result)).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz");
});

it("surfaces read errors without disclosing their raw messages", async () => {
  vi.spyOn(fs, "readFile").mockRejectedValue(Object.assign(new Error("sensitiveRawData"), { code: "EACCES" }));
  const diagnostics: ScanDiagnostic[] = [];
  await new GenericMCPAdapter().discover("/test", diagnostics);
  expect(diagnostics.length).toBeGreaterThan(0);
  expect(JSON.stringify(diagnostics)).not.toContain("sensitiveRawData");
});

it("surfaces rule failures as diagnostics", () => {
  const diagnostics: ScanDiagnostic[] = [];
  const engine = new RiskEngine([{ ...cq002UnrestrictedFilesystem, evaluate: () => { throw new Error("secret"); } }]);
  engine.evaluateAll([{ id: "x", name: "x", sourcePath: "x", adapterName: "test", servers: [] }], diagnostics);
  expect(diagnostics[0].code).toBe("CERQON_RULE_EVALUATION_ERROR");
  expect(JSON.stringify(diagnostics)).not.toContain("secret");
});
