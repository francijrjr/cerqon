import fs from "node:fs/promises";
import path from "node:path";
import type { AgentAdapter, AgentConfiguration } from "@cerqon/types";
import { parseMCPServers } from "./parser-utils.js";

export class VSCodeRooAdapter implements AgentAdapter {
  readonly name = "VS Code / Roo / Cline";

  private candidateRelPaths = [
    path.join(".vscode", "mcp.json"),
    "roo_cline_mcp_settings.json",
    path.join(".cline", "mcp.json"),
    path.join(".roo", "mcp.json"),
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
        const servers = parseMCPServers(parsed.mcpServers || parsed.servers);

        configs.push({
          id: `vscode-${path.basename(filePath)}`,
          name: "VS Code / Roo Code Agent",
          adapterName: this.name,
          sourcePath: filePath,
          servers,
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
