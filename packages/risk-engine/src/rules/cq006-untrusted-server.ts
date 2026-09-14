import type { Rule } from "@cerqon/types";
import { analyzePackageSpec, executionPackageSpecs, sanitizeFinding } from "@cerqon/core";

export const cq006UntrustedServer: Rule = {
  id: "CQ-006", title: "Unverified MCP Source", severity: "high", category: "supply-chain", isImplemented: true,
  description: "Detects mutable package references and direct remote MCP sources without immutable pins.",
  impact: "Mutable dependencies can change without review.",
  recommendation: "Pin registry packages to exact versions and Git sources to full commit hashes; independently review their origin.",
  evaluate({ config }) {
    return config.servers.filter((server) => !server.disabled).flatMap((server) =>
      executionPackageSpecs(server.command, server.args).flatMap((spec) => {
        const analysis = analyzePackageSpec(spec);
        if (!analysis.isMutable) return [];
        return [sanitizeFinding({
          id: `CQ-006-${server.name}-${spec}`, ruleId: "CQ-006", title: "Unverified MCP Source", severity: "high",
          description: analysis.reason, impact: this.impact, recommendation: this.recommendation,
          confidence: analysis.type === "invalid" ? "heuristic" : "confirmed",
          location: { file: config.sourcePath },
          evidence: `Package source: ${spec}`,
          metadata: { serverName: server.name, packageSpec: spec, sourceType: analysis.type },
        })];
      }),
    );
  },
};
