import { describe, it, expect } from "vitest";
import { calculateRiskScore } from "@cerqon/risk-engine";
import type { Finding } from "@cerqon/types";

describe("Risk Score Engine", () => {
  it("should return 100 when there are zero findings", () => {
    const res = calculateRiskScore([]);
    expect(res.score).toBe(100);
    expect(res.summary.totalFindings).toBe(0);
    expect(res.totalDeduction).toBe(0);
  });

  it("should deduce 25 for critical, 15 for high, 7 for medium, 2 for low", () => {
    const findings: Finding[] = [
      {
        id: "1",
        ruleId: "CQ-002",
        title: "Test Critical",
        description: "",
        severity: "critical", // -25
        impact: "",
        recommendation: "",
      },
      {
        id: "2",
        ruleId: "CQ-005",
        title: "Test High",
        description: "",
        severity: "high", // -15
        impact: "",
        recommendation: "",
      },
      {
        id: "3",
        ruleId: "CQ-007",
        title: "Test Medium",
        description: "",
        severity: "medium", // -7
        impact: "",
        recommendation: "",
      },
      {
        id: "4",
        ruleId: "CQ-009",
        title: "Test Low",
        description: "",
        severity: "low", // -2
        impact: "",
        recommendation: "",
      },
    ];

    const res = calculateRiskScore(findings);
    // 100 - (25 + 15 + 7 + 2) = 100 - 49 = 51
    expect(res.score).toBe(51);
    expect(res.summary.critical).toBe(1);
    expect(res.summary.high).toBe(1);
    expect(res.summary.medium).toBe(1);
    expect(res.summary.low).toBe(1);
    expect(res.summary.totalFindings).toBe(4);
  });

  it("should clamp scores so it never drops below 0", () => {
    const findings: Finding[] = Array.from({ length: 10 }, (_, i) => ({
      id: `crit-${i}`,
      ruleId: "CQ-002",
      title: "Critical finding",
      description: "",
      severity: "critical", // -25 * 10 = -250
      impact: "",
      recommendation: "",
    }));

    const res = calculateRiskScore(findings);
    expect(res.score).toBe(0);
  });
});
