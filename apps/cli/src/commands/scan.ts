import { JsonReporter, TerminalReporter, formatSarif } from "@cerqon/reporters";
import { Scanner, ScanTargetNotFoundError } from "@cerqon/scanner";
import { sanitizeUnknownValue } from "@cerqon/core";
import chalk from "chalk";
import fs from "node:fs/promises";
import path from "node:path";
import ora from "ora";
import { z } from "zod";

const ScanOptionsSchema = z.object({
  verbose: z.boolean().optional(),
  json: z.boolean().optional(),
  output: z.string().optional(),
  failOn: z.enum(["critical", "high"]).optional(),
  format: z.enum(["terminal", "json", "sarif"]).optional(),
});

export type ScanCliOptions = z.infer<typeof ScanOptionsSchema>;

export async function handleScanCommand(
  targetPath = ".",
  rawOptions: unknown,
): Promise<void> {
  const parsed = ScanOptionsSchema.safeParse(rawOptions);
  if (!parsed.success) {
    console.error("CERQON_INVALID_USAGE: invalid scan options; --fail-on accepts critical or high.");
    process.exitCode = 2;
    return;
  }
  const options = parsed.data;
  const resolvedTarget = path.resolve(targetPath);

  // If not JSON mode, show nice spinner
  const spinner = options.json
    ? null
    : ora({
        text: `Scanning environment at ${chalk.cyan(String(sanitizeUnknownValue(targetPath)))}...`,
        spinner: "dots",
      }).start();

  try {
    const scanner = new Scanner({ verbose: options.verbose });
    const result = await scanner.scan(resolvedTarget);
    const failed = options.failOn === "high"
      ? result.summary.critical + result.summary.high > 0
      : options.failOn === "critical" && result.summary.critical > 0;
    process.exitCode = result.diagnostics.some((d) => d.code === "CERQON_RULE_EVALUATION_ERROR" || d.code === "CERQON_ADAPTER_DISCOVERY_ERROR") ? 3
      : result.scanStatus !== "complete" ? 2 : failed ? 1 : 0;

    if (spinner) {
      spinner.stop();
    }

    if (options.json || options.format === "json") {
      const jsonReporter = new JsonReporter();
      const output = jsonReporter.format(result);
      if (options.output) {
        await fs.writeFile(path.resolve(options.output), output, "utf-8");
      } else {
        console.log(output);
      }
      return;
    }

    if (options.format === "sarif") {
      const output = formatSarif(result);
      if (options.output) await fs.writeFile(path.resolve(options.output), output, "utf8");
      else process.stdout.write(output + "\n");
      return;
    }

    const terminalReporter = new TerminalReporter();
    const output = terminalReporter.format(result, {
      verbose: options.verbose,
    });
    console.log(output);

    if (options.output) {
      const jsonReporter = new JsonReporter();
      const jsonOutput = jsonReporter.format(result);
      await fs.writeFile(path.resolve(options.output), jsonOutput, "utf-8");
      console.log(
        chalk.green(
          `\nReport successfully saved to ${chalk.bold(options.output)}`,
        ),
      );
    }

  } catch (error) {
    if (spinner) {
      spinner.fail(chalk.red("Scan failed."));
    }
    const missing = error instanceof ScanTargetNotFoundError;
    console.error(missing
      ? `${error.code}\nTarget does not exist: ${sanitizeUnknownValue(targetPath)}`
      : "CERQON_INTERNAL_SCANNER_ERROR: scan or report output could not be completed.");
    process.exitCode = missing ? 2 : 3;
  }
}
