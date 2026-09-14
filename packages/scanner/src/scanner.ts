import fs from "node:fs/promises";
import path from "node:path";
import type { EnvironmentStats, ScanResult, ScanDiagnostic } from "@cerqon/types";
import { AdapterRegistry, readConfiguration } from "@cerqon/adapters";
import { RiskEngine } from "@cerqon/risk-engine";
import { collectSecretValues, sanitizeUnknownValue } from "@cerqon/core";

export class ScanTargetNotFoundError extends Error {
  readonly code = "CERQON_SCAN_TARGET_NOT_FOUND";
  constructor(public readonly targetPath: string) {
    super(`Target does not exist: ${targetPath}`);
    this.name = "ScanTargetNotFoundError";
  }
}

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
    this.version = options.version || "0.1.0-alpha.1";
  }

  async scan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(targetPath);

    // Check if target exists
    let stat;
    try { stat = await fs.stat(resolvedPath); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new ScanTargetNotFoundError(targetPath);
      throw error;
    }
    const diagnostics: ScanDiagnostic[] = [];
    const directConfig = stat.isFile() ? await readConfiguration(resolvedPath, "Generic MCP", diagnostics) : null;
    const configs = stat.isDirectory()
      ? await this.adapterRegistry.discoverAll(resolvedPath, diagnostics)
      : directConfig ? [directConfig] : [];
    if (!stat.isFile() && !stat.isDirectory()) diagnostics.push({ code: "CERQON_INVALID_TARGET", severity: "error", message: "Target must be a regular file or directory.", file: resolvedPath });

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
    const { findings, scoreResult } = this.riskEngine.evaluateAll(configs, diagnostics);

    const durationMs = Date.now() - startTime;

    return sanitizeUnknownValue({
      schemaVersion: "1",
      scanStatus: diagnostics.length ? (configs.length ? "partial" : "failed") : "complete",
      diagnostics,
      cerqonVersion: this.version,
      timestamp: new Date().toISOString(),
      targetPath: resolvedPath,
      score: diagnostics.length ? null : scoreResult.score,
      summary: scoreResult.summary,
      environment,
      findings,
      durationMs,
    }, collectSecretValues(configs)) as ScanResult;
  }
}
