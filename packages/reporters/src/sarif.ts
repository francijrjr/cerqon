import type { ScanResult } from "@cerqon/types";
import { sanitizeUnknownValue } from "@cerqon/core";

export interface SarifReport {
  version: "2.1.0";
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  runs: Array<{ tool: { driver: { name: string; informationUri: string; rules: unknown[] } }; results: unknown[] }>;
}

export function formatSarif(result: ScanResult): string {
  const ruleMap = new Map(result.findings.map((finding) => [finding.ruleId, finding]));
  const rules = [...ruleMap.values()].map((finding) => ({ id: finding.ruleId, name: finding.title, shortDescription: { text: finding.title }, help: { text: finding.recommendation }, properties: { severity: finding.severity } }));
  const results = result.findings.map((finding) => ({ ruleId: finding.ruleId, level: finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "info" ? "note" : "warning", message: { text: finding.description }, locations: finding.location?.file ? [{ physicalLocation: { artifactLocation: { uri: finding.location.file.replace(/\\/g, "/") } } }] : undefined }));
  return JSON.stringify(sanitizeUnknownValue({ version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: "CERQON", informationUri: "https://github.com/francijrjr/cerqon", rules } }, results }] }), null, 2);
}
