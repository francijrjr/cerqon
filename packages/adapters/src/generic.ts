import fs from "node:fs/promises";
import path from "node:path";
import type { AgentAdapter, AgentConfiguration } from "@cerqon/types";
import { parseMCPServers } from "./parser-utils.js";

export class GenericMCPAdapter implements AgentAdapter {
  readonly name = "Generic MCP";

  private candidateRelPaths = [
    "mcp.json",
    "mcp-servers.json",
    "mcp_servers.json",
    path.join(".mcp", "config.json"),
    "cerqon.agent.json",
  ];

  async detect(targetDir: string): Promise<boolean> {
    for (const rel of this.candidateRelPaths) {
      try {
        await fs.access(path.join(targetDir, rel));
        return true;
      } catch {
        // Continue
      }
    }
    return false;
  }

  async discover(targetDir: string): Promise<AgentConfiguration[]> {
    const configs: AgentConfiguration[] = [];

    for (const rel of this.candidateRelPaths) {
      const filePath = path.join(targetDir, rel);
      try {
        const raw = await fs.readFile(filePath, "utf-8");
        const parsed = JSON.parse(raw);
        const servers = parseMCPServers(parsed.mcpServers || parsed.servers || (parsed.command ? { default: parsed } : {}));

        configs.push({
          id: `generic-${path.basename(filePath)}`,
          name: parsed.name || "Generic AI Agent",
          adapterName: this.name,
          sourcePath: filePath,
          servers,
          tools: parsed.tools,
          envVars: parsed.env,
          metadata: {
            rawFile: filePath,
          },
        });
      } catch {
        // Skip
      }
    }

    return configs;
  }
}
