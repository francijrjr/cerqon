import type { AgentAdapter, AgentConfiguration, ScanDiagnostic } from "@cerqon/types";
import { ClaudeDesktopAdapter } from "./claude.js";
import { CursorAdapter } from "./cursor.js";
import { VSCodeRooAdapter } from "./vscode.js";
import { GenericMCPAdapter } from "./generic.js";
import fs from "node:fs/promises";
import path from "node:path";

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
    const directories: string[] = [];
    const excluded = new Set([".git", "node_modules", "dist", "build", "coverage", ".next", ".cache", "vendor"]);
    const walk = async (dir: string, depth: number): Promise<void> => {
      directories.push(dir);
      if (depth >= 4) return;
      let entries;
      try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
      for (const entry of entries) {
        if (!entry.isDirectory() || excluded.has(entry.name) || entry.isSymbolicLink()) continue;
        await walk(path.join(dir, entry.name), depth + 1);
      }
    };
    await walk(targetDir, 0);

    for (const directory of directories) for (const adapter of this.adapters) {
      try {
        if (!await adapter.detect(directory)) continue;
        const configs = await adapter.discover(directory, diagnostics);
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
