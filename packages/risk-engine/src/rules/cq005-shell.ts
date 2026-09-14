import type { Finding, Rule, RuleContext } from "@cerqon/types";
import { detectShellCapability } from "@cerqon/core";

export const cq005UnsafeShell: Rule = {
  id: "CQ-005",
  title: "Dangerous Shell Capability",
  description:
    "Detects MCP servers or agent tools providing terminal command execution capabilities.",
  severity: "high",
  category: "execution",
  isImplemented: true,
  impact:
    "Arbitrary shell access enables unconstrained command execution, privilege escalation, or lateral network movement if the agent prompt is manipulated.",
  recommendation:
    "Require explicit human confirmation before arbitrary command execution or constrain execution inside an ephemeral sandbox.",
  references: [
    "https://cwe.mitre.org/data/definitions/78.html",
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  ],
  evaluate(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { config } = context;

    // Check MCP servers
    for (const server of config.servers) {
      const check = detectShellCapability(server.command, server.args, server.name);
      if (check.hasShellCapability) {
        findings.push({
          id: `CQ-005-server-${server.name}`,
          ruleId: "CQ-005",
          title: "Unsafe Shell Capability",
          description: `MCP server '${server.name}' provides terminal command execution capability (${check.shellType || "shell"}).`,
          severity: "high",
          location: {
            file: config.sourcePath,
          },
          evidence: `Agent: ${config.name}\nCapability: ${check.shellType || "shell"}\nReason: ${check.reason}`,
          impact:
            "The agent can execute arbitrary shell commands without an explicit approval policy.",
          recommendation:
            "Require explicit human confirmation before arbitrary command execution.",
          metadata: {
            agentName: config.name,
            serverName: server.name,
            shellType: check.shellType,
            command: server.command,
          },
        });
      }
    }

    // Check declared agent tools
    if (config.tools) {
      for (const tool of config.tools) {
        const check = detectShellCapability(undefined, undefined, tool.name);
        if (check.hasShellCapability) {
          findings.push({
            id: `CQ-005-tool-${tool.name}`,
            ruleId: "CQ-005",
            title: "Unsafe Shell Capability",
            description: `Tool '${tool.name}' exposes direct command line or shell execution capabilities.`,
            severity: "high",
            location: {
              file: config.sourcePath,
            },
            evidence: `Tool: ${tool.name}\nCapability: ${check.shellType || "shell"}\nReason: ${check.reason}`,
            impact:
              "The agent can execute arbitrary shell commands without an explicit approval policy.",
            recommendation:
              "Require explicit human confirmation before arbitrary command execution.",
            metadata: {
              agentName: config.name,
              toolName: tool.name,
              shellType: check.shellType,
            },
          });
        }
      }
    }

    return findings;
  },
};
