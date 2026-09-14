import { createHash } from "node:crypto";
import type { Finding } from "@cerqon/types";
import { SEVERITY_WEIGHTS } from "./score.js";

export function findingFingerprint(finding: Finding): string {
  if (finding.fingerprint) return `${finding.ruleId}:${finding.fingerprint}`;
  const metadata = finding.metadata ?? {};
  const target = metadata.targetPath ?? metadata.key ?? metadata.url ?? metadata.packageSpec;
  const identity = [finding.ruleId, finding.location?.file, finding.location?.line, finding.location?.column,
    metadata.serverName ?? metadata.toolName, target, finding.title,
    target === undefined ? (finding.evidence?.trim() ?? finding.description) : undefined];
  return createHash("sha256").update(JSON.stringify(identity)).digest("hex");
}

/** Prefer the most severe duplicate; tie-breaking and output order are deterministic. */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    const key = findingFingerprint(finding);
    const previous = unique.get(key);
    if (!previous || SEVERITY_WEIGHTS[finding.severity] > SEVERITY_WEIGHTS[previous.severity] ||
      (finding.severity === previous.severity && JSON.stringify(finding) < JSON.stringify(previous))) unique.set(key, finding);
  }
  return [...unique.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, finding]) => finding);
}
