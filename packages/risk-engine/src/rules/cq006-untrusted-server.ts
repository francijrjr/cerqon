import type { Finding, Rule, RuleContext } from "@cerqon/types";

export const cq006UntrustedServer: Rule = {
  id: "CQ-006",
  title: "Unverified MCP Source",
  description: "Detects mutable package references and direct remote MCP sources.",
  severity: "high", category: "supply-chain", isImplemented: true,
  impact: "Mutable dependencies can change without review.",
  recommendation: "Pin registry packages to exact versions and Git sources to full commit hashes; independently review their origin.",
  evaluate(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { config } = context;
    for (const server of config.servers) {
      if (server.disabled) continue;
      // 3. Check unpinned remote source in command or args (e.g. npx with direct git/http url)
      if (server.args) {
        const hasPinnedNpxPackage = server.command === "npx" && server.args.some((arg) => /@[0-9]+(?:\.[0-9]+)*/.test(arg));
        const hasUnpinnedRemote = !hasPinnedNpxPackage && server.args.some(
          (arg) =>
            arg.startsWith("git+") ||
            arg.startsWith("https://") ||
            arg.startsWith("http://") ||
            arg.startsWith("github:") ||
            (/^@?[\w.-]+(?:\/[\w.-]+)?$/.test(arg) && server.command === "npx" && !arg.startsWith(".") && !arg.includes("@")) ||
            (server.command === "npx" && /@latest$/.test(arg))
        );
        if (hasUnpinnedRemote) {
          findings.push({
            id: `CQ-006-${server.name}-unpinned-remote`,
            ruleId: "CQ-006",
            title: "Untrusted MCP Server (Unpinned Remote Source)",
            description: `MCP Server '${server.name}' executes unpinned remote code directly from repository URL.`,
            severity: "high",
            location: {
              file: config.sourcePath,
            },
            evidence: `Server: ${server.name}\nCommand: ${server.command} ${server.args.join(" ")}`,
            impact:
              "Executing packages directly from remote git repositories without cryptographic pinning introduces supply chain tampering risks.",
            recommendation:
              "Pin packages to specific immutable release versions or hashes.",
            metadata: {
              serverName: server.name,
            },
          });
        }
      }
    }

    return findings;
  },
};
