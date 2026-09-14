import path from "node:path";
import { describe, it, expect } from "vitest";
import { Scanner } from "@cerqon/scanner";

describe("Scanner End-to-End", () => {
  const insecurePath = path.resolve("./examples/insecure-agent");
  const securePath = path.resolve("./examples/secure-agent");

  it("should scan insecure-agent and identify all severe vulnerabilities with score 0", async () => {
    const scanner = new Scanner();
    const result = await scanner.scan(insecurePath);

    expect(result.environment.agents).toBe(1);
    expect(result.environment.mcpServers).toBe(3);
    expect(result.score).toBe(0);
    expect(result.summary.critical).toBeGreaterThanOrEqual(4);
    expect(result.summary.high).toBeGreaterThanOrEqual(3);

    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("CQ-002");
    expect(ruleIds).toContain("CQ-003");
    expect(ruleIds).toContain("CQ-005");
    expect(ruleIds).toContain("CQ-006");

    // Check that secrets are masked
    const secretFindings = result.findings.filter((f) => f.ruleId === "CQ-003");
    for (const sf of secretFindings) {
      expect(sf.description).toContain("****");
      expect(sf.evidence).toContain("****");
    }
  });

  it("should scan secure-agent and report 0 findings with 100 score", async () => {
    const scanner = new Scanner();
    const result = await scanner.scan(securePath);

    expect(result.environment.agents).toBe(1);
    expect(result.environment.mcpServers).toBe(2);
    expect(result.score).toBe(100);
    expect(result.findings).toHaveLength(0);
    expect(result.summary.totalFindings).toBe(0);
  });
});
