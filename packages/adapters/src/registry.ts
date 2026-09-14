import type { AgentAdapter, AgentConfiguration, ScanDiagnostic } from "@cerqon/types";
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

  async discoverAll(targetDir: string, diagnostics: ScanDiagnostic[] = []): Promise<AgentConfiguration[]> {
    const allConfigs: AgentConfiguration[] = [];
    const seenPaths = new Set<string>();

    for (const adapter of this.adapters) {
      try {
        const configs = await adapter.discover(targetDir, diagnostics);
        for (const cfg of configs) {
          if (!seenPaths.has(cfg.sourcePath)) {
            seenPaths.add(cfg.sourcePath);
            allConfigs.push(cfg);
          }
        }
      } catch {
        diagnostics.push({ code: "CERQON_ADAPTER_DISCOVERY_ERROR", severity: "error", message: "Adapter discovery failed.", file: targetDir, adapter: adapter.name });
      }
    }

    return allConfigs;
  }
}
