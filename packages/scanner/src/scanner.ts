import fs from "node:fs/promises";
import path from "node:path";
import type { EnvironmentStats, ScanResult } from "@cerqon/types";
import { AdapterRegistry } from "@cerqon/adapters";
import { RiskEngine } from "@cerqon/risk-engine";

export interface ScannerOptions {
  version?: string;
  verbose?: boolean;
}

export class Scanner {
  private adapterRegistry: AdapterRegistry;
  private riskEngine: RiskEngine;
  private version: string;

  constructor(options: ScannerOptions = {}) {
    this.adapterRegistry = new AdapterRegistry();
    this.riskEngine = new RiskEngine();
    this.version = options.version || "0.1.0";
  }

  async scan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(targetPath);

    // Check if target exists
    const stat = await fs.stat(resolvedPath);
    const targetDir = stat.isDirectory() ? resolvedPath : path.dirname(resolvedPath);

    // Discovery phase via registered adapters
    const configs = await this.adapterRegistry.discoverAll(targetDir);

    // If scanning a direct file not captured yet, attempt generic parsing
    if (!stat.isDirectory() && configs.length === 0) {
      const genericAdapter = this.adapterRegistry
        .getAdapters()
        .find((a) => a.name === "Generic MCP");
      if (genericAdapter) {
        const discovered = await genericAdapter.discover(targetDir);
        configs.push(...discovered);
      }
    }

    // Compute environment statistics
    const environment: EnvironmentStats = {
      agents: configs.length,
      mcpServers: 0,
      tools: 0,
      integrations: 0,
    };

    for (const config of configs) {
      environment.mcpServers += config.servers.length;
      if (config.tools) {
        environment.tools += config.tools.length;
      }
      // Count servers with remote url or external commands as integrations
      for (const server of config.servers) {
        if (server.url || (server.command && server.command !== "node")) {
          environment.integrations += 1;
        }
      }
    }

    // Risk correlation & scoring
    const { findings, scoreResult } = this.riskEngine.evaluateAll(configs);

    const durationMs = Date.now() - startTime;

    return {
      cerqonVersion: this.version,
      timestamp: new Date().toISOString(),
      targetPath: resolvedPath,
      score: scoreResult.score,
      summary: scoreResult.summary,
      environment,
      findings,
      durationMs,
    };
  }
}
