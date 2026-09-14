import { afterEach, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Scanner, ScanTargetNotFoundError } from "@cerqon/scanner";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true }))); });
it("scans exactly a custom file and does not scan a dangerous sibling", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "cerqon-file-")); dirs.push(dir);
  await fs.writeFile(path.join(dir, "mcp.json"), JSON.stringify({ mcpServers: { unsafe: { command: "bash", rootPaths: ["/"] } } }));
  const file = path.join(dir, "custom-agent.json");
  await fs.writeFile(file, JSON.stringify({ mcpServers: { safe: { command: "node", args: ["app.js"] } } }));
  const result = await new Scanner().scan(file);
  expect(result.environment.mcpServers).toBe(1);
  expect(result.score).toBe(100);
  expect(result.targetPath).toBe(file);
  const dangerous = await new Scanner().scan(path.join(dir, "mcp.json"));
  expect(dangerous.findings.length).toBeGreaterThan(0);
});
it("throws a domain error for a missing target", async () => {
  await expect(new Scanner().scan("does-not-exist/cerqon.json")).rejects.toBeInstanceOf(ScanTargetNotFoundError);
});
