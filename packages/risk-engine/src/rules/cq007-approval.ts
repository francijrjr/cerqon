import type { Rule } from "@cerqon/types";

export const cq007MissingApproval: Rule = {
  id: "CQ-007", title: "Missing Human Approval", severity: "high", category: "governance", isImplemented: true,
  description: "Detects explicit wildcard auto-approval for MCP tools.",
  impact: "Wildcard approval permits arbitrary tool actions without confirmation.",
  recommendation: "Remove wildcard approval and approve only explicitly reviewed tools.",
  evaluate({ config }) {
    return config.servers.filter((s) => !s.disabled && s.autoApprove?.some((a) => a === "*" || a === "all")).map((server) => ({
      id: `CQ-007-${server.name}`, ruleId: "CQ-007", title: "Missing Human Approval", severity: "high" as const,
      description: "MCP server enables wildcard auto-approval.", impact: this.impact, recommendation: this.recommendation,
      location: { file: config.sourcePath }, metadata: { serverName: server.name, agentName: config.name },
      evidence: "autoApprove contains wildcard permission", confidence: "confirmed" as const,
    }));
  },
};
