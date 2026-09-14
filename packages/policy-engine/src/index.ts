import type { Finding, Severity } from "@cerqon/types";

export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  failOnSeverity?: Severity;
  minScoreThreshold?: number;
  blockedTools?: string[];
  deniedPaths?: string[];
}

export interface PolicyValidationResult {
  passed: boolean;
  violations: string[];
}

export class PolicyEngine {
  validateScanResult(
    score: number,
    findings: Finding[],
    policy?: PolicyRule
  ): PolicyValidationResult {
    const violations: string[] = [];

    if (!policy) {
      return { passed: true, violations: [] };
    }

    if (policy.minScoreThreshold !== undefined && score < policy.minScoreThreshold) {
      violations.push(
        `Security score ${score} is below the required policy threshold of ${policy.minScoreThreshold}`
      );
    }

    if (policy.failOnSeverity) {
      const severityOrder: Record<Severity, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
        info: 0,
      };
      const minLevel = severityOrder[policy.failOnSeverity];

      for (const finding of findings) {
        if (severityOrder[finding.severity] >= minLevel) {
          violations.push(
            `Finding [${finding.ruleId}] '${finding.title}' violates fail-on '${policy.failOnSeverity}' policy`
          );
        }
      }
    }

    return {
      passed: violations.length === 0,
      violations,
    };
  }
}
