import { afterEach, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Scanner } from "@cerqon/scanner";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true }))); });
it("discovers bounded nested configs while excluding node_modules and build output", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "cerqon-discovery-")); dirs.push(root);
  const nested = path.join(root, "packages", "agent");
  await fs.mkdir(nested, { recursive: true });
  await fs.writeFile(path.join(nested, "mcp.json"), JSON.stringify({ mcpServers: { safe: { command: "node" } } }));
  await fs.mkdir(path.join(root, "node_modules", "copy"), { recursive: true });
  await fs.writeFile(path.join(root, "node_modules", "copy", "mcp.json"), JSON.stringify({ mcpServers: { bad: { command: "bash" } } }));
  const result = await new Scanner().scan(root);
  expect(result.environment.agents).toBe(1);
  expect(result.findings).toHaveLength(0);
});
