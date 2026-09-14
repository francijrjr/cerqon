import { expect, it } from "vitest";
import { formatSarif } from "@cerqon/reporters";
import type { ScanResult } from "@cerqon/types";

it("emits valid SARIF 2.1.0 without raw secrets", () => {
  const raw = "ghp_abcdefghijklmnopqrstuvwxyz";
  const result = { schemaVersion: "1", scanStatus: "complete", diagnostics: [], cerqonVersion: "0.1.0", timestamp: "2026-01-01T00:00:00Z", targetPath: ".", score: null, summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, totalFindings: 1 }, environment: { agents: 1, mcpServers: 1, tools: 0, integrations: 0 }, findings: [{ id: "1", ruleId: "CQ-003", title: "Secret", description: raw, severity: "critical" as const, impact: "", recommendation: "", location: { file: "mcp.json" } }], durationMs: 1 } satisfies ScanResult;
  const sarif = JSON.parse(formatSarif(result));
  expect(sarif.version).toBe("2.1.0"); expect(sarif.runs[0].results).toHaveLength(1); expect(JSON.stringify(sarif)).not.toContain(raw);
});
