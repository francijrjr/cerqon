import type { Finding, Rule, RuleContext } from "@cerqon/types";
import { assessPathSafety } from "@cerqon/core";

export const cq002UnrestrictedFilesystem: Rule = {
  id: "CQ-002",
  title: "Unrestricted Filesystem Access",
  description:
    "Identifies MCP servers or agent tools configured with unrestricted or root filesystem access.",
  severity: "critical",
  category: "filesystem",
  isImplemented: true,
  impact:
    "The AI agent may access, read, or overwrite files outside the expected project scope, exposing system binaries, configuration, and sensitive user files.",
  recommendation:
    "Restrict filesystem access to explicitly required project directories instead of mounting the root directory.",
  references: [
    "https://modelcontextprotocol.io/docs/concepts/resources",
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  ],
  evaluate(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { config } = context;

    for (const server of config.servers) {
      if (server.disabled) continue;
      // Check explicit rootPaths or paths in arguments
      const pathsToCheck: string[] = [];
      if (server.rootPaths) {
        pathsToCheck.push(...server.rootPaths);
      }

      // Check args if server name indicates filesystem
      if (
        server.name.toLowerCase().includes("filesystem") ||
        server.command?.includes("server-filesystem") ||
        server.args?.some((a) => a.includes("server-filesystem"))
      ) {
        if (server.args) {
          for (const arg of server.args) {
            if (!arg.startsWith("-") && !arg.includes("server-filesystem")) {
              pathsToCheck.push(arg);
            }
          }
        }
      }

      const uniquePaths = Array.from(new Set(pathsToCheck));
      for (const p of uniquePaths) {
        const assessment = assessPathSafety(p);
        if (assessment.isDangerous) {
          findings.push({
            id: `CQ-002-${server.name}-${p.replace(/[^a-zA-Z0-9]/g, "_")}`,
            ruleId: "CQ-002",
            title: "Unrestricted Filesystem Access",
            description: `MCP Server '${server.name}' mounts dangerous path '${p}'. ${assessment.reason || ""}`,
            severity: "critical",
            location: {
              file: config.sourcePath,
            },
            evidence: `MCP Server: ${server.name}\nPath: ${p}`,
            impact:
              "The AI agent may access, read, or overwrite files outside the expected project scope.",
            recommendation:
              "Restrict the MCP filesystem server to explicitly required project directories.",
            metadata: {
              agentName: config.name,
              serverName: server.name,
              targetPath: p,
              isRoot: assessment.isRoot,
            },
          });
        }
      }
    }

    return findings;
  },
};
