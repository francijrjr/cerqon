import { afterEach, expect, it, vi } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Scanner } from "@cerqon/scanner";
import { JsonReporter, TerminalReporter } from "@cerqon/reporters";
import { handleScanCommand } from "../apps/cli/src/commands/scan.js";
import { cq005UnsafeShell, cq008UnsafeTransport } from "@cerqon/risk-engine";

const dirs: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); process.exitCode = 0; await Promise.all(dirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true }))); });
it("redacts secrets across entire results and both reporter paths", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "cerqon-redaction-")); dirs.push(dir);
  const raw = "ghp_abcdefghijklmnopqrstuvwxyz";
  const awsSecret = "plaintextAwsSecret0123456789";
  await fs.writeFile(path.join(dir, "mcp.json"), JSON.stringify({
    name: raw, metadata: { credentials: { token: awsSecret } },
    mcpServers: {
      remote: { url: "http://username:password987@example.com", autoApprove: ["*"] },
      source: { command: "npx", args: [`git+https://${raw}@github.com/org/repo`] },
      shell: { command: "bash", args: ["--token", raw], env: { AWS_SECRET_ACCESS_KEY: awsSecret }, rootPaths: ["/"] },
    },
  }));
  const result = await new Scanner().scan(dir);
  expect(result.scanStatus).toBe("complete");
  expect(result.summary.totalFindings).toBe(result.findings.length);
  for (const output of [JSON.stringify(result), new JsonReporter().format(result), new TerminalReporter().format(result, { verbose: true })]) {
    for (const secret of [raw, awsSecret, "username", "password987"]) expect(output).not.toContain(secret);
  }
  const json = JSON.parse(new JsonReporter().format(result));
  expect(Object.keys(json)).toEqual(expect.arrayContaining(["schemaVersion", "scanStatus", "diagnostics", "durationMs", "findings"]));
});
it("reports unexpected scanner failures with exit 3 without logging the exception payload", async () => {
  vi.spyOn(Scanner.prototype, "scan").mockRejectedValue(new Error("rawSensitiveExceptionPayload"));
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  await handleScanCommand(".", { json: true });
  expect(process.exitCode).toBe(3);
  expect(JSON.stringify(stderr.mock.calls)).not.toContain("rawSensitiveExceptionPayload");
});
it("does not infer shell capability from documentation", () => {
  const config = { id: "x", name: "x", sourcePath: "x", adapterName: "test", servers: [{ name: "app", command: "node", args: ["app.js"] }], tools: [{ name: "read_file", description: "documentation about bash" }] };
  expect(cq005UnsafeShell.evaluate({ config })).toEqual([]);
});
it("does not confuse loopback with a hostname or URL containing localhost", () => {
  const config = { id: "x", name: "x", sourcePath: "x", adapterName: "test", servers: [
    { name: "bad", url: "http://localhost.evil.example/mcp" }, { name: "bad2", url: "http://example.com/127.0.0.1" },
    { name: "local", url: "http://127.0.0.1:4000" },
  ] };
  expect(cq008UnsafeTransport.evaluate({ config })).toHaveLength(2);
});
