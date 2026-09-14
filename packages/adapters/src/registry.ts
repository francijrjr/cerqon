import type { AgentAdapter, AgentConfiguration } from "@cerqon/types";
import { ClaudeDesktopAdapter } from "./claude.js";
import { CursorAdapter } from "./cursor.js";
import { VSCodeRooAdapter } from "./vscode.js";
import { GenericMCPAdapter } from "./generic.js";

export class AdapterRegistry {
  private adapters: AgentAdapter[] = [];

  constructor() {
    this.registerDefaultAdapters();
  }

  registerDefaultAdapters(): void {
    this.adapters = [
      new ClaudeDesktopAdapter(),
      new CursorAdapter(),
      new VSCodeRooAdapter(),
      new GenericMCPAdapter(),
    ];
  }

  registerAdapter(adapter: AgentAdapter): void {
    this.adapters.push(adapter);
  }

  getAdapters(): AgentAdapter[] {
    return [...this.adapters];
  }

  async discoverAll(targetDir: string): Promise<AgentConfiguration[]> {
    const allConfigs: AgentConfiguration[] = [];
    const seenPaths = new Set<string>();

    for (const adapter of this.adapters) {
      const isDetected = await adapter.detect(targetDir);
      if (isDetected) {
        const configs = await adapter.discover(targetDir);
        for (const cfg of configs) {
          if (!seenPaths.has(cfg.sourcePath)) {
            seenPaths.add(cfg.sourcePath);
            allConfigs.push(cfg);
          }
        }
      }
    }

    return allConfigs;
  }
}
