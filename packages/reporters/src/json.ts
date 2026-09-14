import type { ScanResult } from "@cerqon/types";

export interface JsonReporterOptions {
  pretty?: boolean;
}

export class JsonReporter {
  format(result: ScanResult, options: JsonReporterOptions = { pretty: true }): string {
    const output = {
      cerqonVersion: result.cerqonVersion,
      timestamp: result.timestamp,
      targetPath: result.targetPath,
      score: result.score,
      summary: result.summary,
      environment: result.environment,
      findings: result.findings,
    };

    return options.pretty
      ? JSON.stringify(output, null, 2)
      : JSON.stringify(output);
  }
}
