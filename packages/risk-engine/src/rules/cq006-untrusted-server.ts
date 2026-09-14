import type { Finding, Rule, RuleContext } from "@cerqon/types";

export const cq006UntrustedServer: Rule = {
  id: "CQ-006",
  title: "Unverified MCP Source",
  description:
    "Flags MCP sources that are remote or lack an immutable package/version pin. Transport and approval policy are separate concerns.",
  severity: "high",
  category: "supply-chain",
  isImplemented: true,
  impact:
    "Interacting with unauthenticated or unencrypted MCP servers exposes communication to interception, manipulation, or unauthorized prompt injections.",
  recommendation:
    "Use encrypted HTTPS transports, avoid raw IP endpoints, verify source integrity, and restrict auto-approval permissions.",
  references: [
    "https://modelcontextprotocol.io/docs/concepts/architecture",
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
  ],
  evaluate(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { config } = context;

    for (const server of config.servers) {
      if (server.disabled) continue;
      // 1. Check unencrypted HTTP transport
      if (server.url && server.url.startsWith("http://")) {
        // Exclude localhost/127.0.0.1 for local dev unless explicitly wanted
        const isLocal =
          server.url.includes("localhost") || server.url.includes("127.0.0.1");
        if (!isLocal) {
          findings.push({
            id: `CQ-006-${server.name}-unencrypted-http`,
            ruleId: "CQ-006",
            title: "Untrusted MCP Server (Unencrypted HTTP)",
            description: `MCP Server '${server.name}' communicates over unencrypted HTTP: ${server.url}`,
            severity: "high",
            location: {
              file: config.sourcePath,
            },
            evidence: `Server: ${server.name}\nURL: ${server.url}`,
            impact:
              "Cleartext transmission exposes agent prompts, context data, and responses to network eavesdropping and tampering.",
            recommendation:
              "Enforce TLS (HTTPS/WSS) for all remote MCP server connections.",
            metadata: {
              agentName: config.name,
              serverName: server.name,
              url: server.url,
            },
          });
        }
      }

      // 2. Check wildcard auto-approval
      if (
        server.autoApprove &&
        (server.autoApprove.includes("*") || server.autoApprove.includes("all"))
      ) {
        findings.push({
          id: `CQ-006-${server.name}-wildcard-approval`,
          ruleId: "CQ-006",
          title: "Untrusted MCP Server (Wildcard Auto-Approval)",
          description: `MCP Server '${server.name}' enables wildcard auto-approval for all tool executions.`,
          severity: "high",
          location: {
            file: config.sourcePath,
          },
          evidence: `Server: ${server.name}\nautoApprove: ${JSON.stringify(server.autoApprove)}`,
          impact:
            "Wildcard approval completely bypasses human-in-the-loop oversight, allowing the agent to perform destructive actions autonomously.",
          recommendation:
            "Remove wildcard auto-approval and specify explicit whitelisted tool names.",
          metadata: {
            agentName: config.name,
            serverName: server.name,
            autoApprove: server.autoApprove,
          },
        });
      }

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
