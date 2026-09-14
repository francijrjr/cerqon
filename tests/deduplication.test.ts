import { expect, it } from "vitest";
import { calculateRiskScore, deduplicateFindings, RiskEngine, cq002UnrestrictedFilesystem } from "@cerqon/risk-engine";
import type { Finding } from "@cerqon/types";

const finding: Finding = { id: "one", ruleId: "CQ-002", title: "Root", description: "Root", severity: "high", impact: "", recommendation: "", location: { file: "/test" }, metadata: { serverName: "one", targetPath: "/" } };
it("deduplicates by stable target instead of generated display ID", () => {
  expect(deduplicateFindings([finding, { ...finding, id: "two" }])).toHaveLength(1);
  expect(deduplicateFindings([finding, { ...finding, metadata: { ...finding.metadata, serverName: "two" } }])).toHaveLength(2);
});
it("resolves conflicting severity conservatively and independently of ordering", () => {
  const items = [finding, { ...finding, severity: "critical" as const }];
  expect(deduplicateFindings(items)).toEqual(deduplicateFindings([...items].reverse()));
  expect(deduplicateFindings(items)[0].severity).toBe("critical");
});
it("returns exactly the findings that were counted in the summary", () => {
  const engine = new RiskEngine([{ ...cq002UnrestrictedFilesystem, evaluate: () => [finding, { ...finding, id: "duplicate" }] }]);
  const result = engine.evaluateAll([{ id: "x", name: "x", adapterName: "test", sourcePath: "test", servers: [] }]);
  expect(result.findings).toHaveLength(1);
  expect(result.scoreResult.summary.totalFindings).toBe(result.findings.length);
});
it("scores deterministically within bounds and does not penalize info", () => {
  const items = [finding, { ...finding, id: "info", severity: "info" as const }];
  expect(calculateRiskScore(items)).toEqual(calculateRiskScore([...items].reverse()));
  expect(calculateRiskScore(items).score).toBe(85);
  expect(calculateRiskScore([]).score).toBe(100);
  expect(calculateRiskScore(Array(50).fill(finding)).score).toBe(0);
});
