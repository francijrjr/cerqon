import type { Rule } from "@cerqon/types";

const broad = new Set(["*", "all", "admin", "unrestricted"]);
export const cq001ExcessiveToolPermission: Rule = {
  id: "CQ-001", title: "Excessive Tool Permission", severity: "high", category: "permissions", isImplemented: true,
  description: "Detects structured wildcard or administrator tool permissions.",
  impact: "Broad tool permissions allow actions beyond the agent's intended scope.", recommendation: "Replace broad permissions with the smallest explicit action set.",
  evaluate({ config }) {
    return (config.tools ?? []).filter((tool) => (tool.permissions ?? []).some((permission) => broad.has(permission.toLowerCase()))).map((tool) => ({
      id: `CQ-001-${tool.name}`, ruleId: "CQ-001", title: "Excessive Tool Permission", severity: "high" as const,
      description: `Tool '${tool.name}' declares a broad structured permission.`, impact: this.impact, recommendation: this.recommendation,
      location: { file: config.sourcePath }, evidence: `Tool: ${tool.name}; permissions: ${tool.permissions?.join(", ")}`, metadata: { toolName: tool.name, permissions: tool.permissions }, confidence: "confirmed" as const,
    }));
  },
};
