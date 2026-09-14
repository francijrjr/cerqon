import type { ScanResult } from "@cerqon/types";
import { sanitizeUnknownValue } from "@cerqon/core";

export interface JsonReporterOptions {
  pretty?: boolean;
}

export class JsonReporter {
  format(result: ScanResult, options: JsonReporterOptions = { pretty: true }): string {
    const output = {
      schemaVersion: result.schemaVersion,
      scanStatus: result.scanStatus,
      diagnostics: result.diagnostics,
      durationMs: result.durationMs,
      cerqonVersion: result.cerqonVersion,
      timestamp: result.timestamp,
      targetPath: result.targetPath,
      score: result.score,
      summary: result.summary,
      environment: result.environment,
      findings: result.findings,
    };

    return options.pretty
      ? JSON.stringify(sanitizeUnknownValue(output), null, 2)
      : JSON.stringify(sanitizeUnknownValue(output));
  }
}
