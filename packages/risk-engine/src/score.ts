import type { Finding, ScanSummary, Severity } from "@cerqon/types";

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 7,
  low: 2,
  info: 0,
};

export interface ScoreCalculationResult {
  score: number;
  summary: ScanSummary;
  totalDeduction: number;
}

export function calculateRiskScore(findings: Finding[]): ScoreCalculationResult {
  const summary: ScanSummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    totalFindings: findings.length,
  };

  let totalDeduction = 0;

  for (const finding of findings) {
    const sev = finding.severity || "info";
    summary[sev] = (summary[sev] || 0) + 1;
    totalDeduction += SEVERITY_WEIGHTS[sev] || 0;
  }

  // Base score is 100, bounded between [0, 100]
  const rawScore = 100 - totalDeduction;
  const score = Math.max(0, Math.min(100, rawScore));

  return {
    score,
    summary,
    totalDeduction,
  };
}
