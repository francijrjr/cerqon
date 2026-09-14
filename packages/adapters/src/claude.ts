import fs from "node:fs/promises";
import path from "node:path";
import type { AgentAdapter, AgentConfiguration } from "@cerqon/types";
import { parseMCPServers } from "./parser-utils.js";

export class ClaudeDesktopAdapter implements AgentAdapter {
  readonly name = "Claude Desktop";

  private candidateFilenames = [
    "claude_desktop_config.json",
    "claude-desktop-config.json",
    "claude_desktop.json",
  ];

  async detect(targetDir: string): Promise<boolean> {
    for (const filename of this.candidateFilenames) {
      try {
        const filePath = path.join(targetDir, filename);
        await fs.access(filePath);
        return true;
      } catch {
        // Continue
      }
    }
    return false;
  }

  async discover(targetDir: string): Promise<AgentConfiguration[]> {
    const configs: AgentConfiguration[] = [];

    for (const filename of this.candidateFilenames) {
      const filePath = path.join(targetDir, filename);
      try {
        const raw = await fs.readFile(filePath, "utf-8");
        const parsed = JSON.parse(raw);
        const servers = parseMCPServers(parsed.mcpServers || parsed.servers);

        configs.push({
          id: `claude-${path.basename(filePath)}`,
          name: "Claude Desktop",
          adapterName: this.name,
          sourcePath: filePath,
          servers,
          envVars: parsed.env,
          metadata: {
            rawFile: filePath,
          },
        });
      } catch {
        // Skip invalid/missing files
      }
    }

    return configs;
  }
}
