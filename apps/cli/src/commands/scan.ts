import fs from "node:fs/promises";
import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import { z } from "zod";
import { Scanner } from "@cerqon/scanner";
import { JsonReporter, TerminalReporter } from "@cerqon/reporters";

const ScanOptionsSchema = z.object({
  verbose: z.boolean().optional(),
  json: z.boolean().optional(),
  output: z.string().optional(),
});

export type ScanCliOptions = z.infer<typeof ScanOptionsSchema>;

export async function handleScanCommand(
  targetPath = ".",
  rawOptions: unknown
): Promise<void> {
  const options = ScanOptionsSchema.parse(rawOptions);
  const resolvedTarget = path.resolve(targetPath);

  // If not JSON mode, show nice spinner
  const spinner = options.json
    ? null
    : ora({
        text: `Scanning environment at ${chalk.cyan(targetPath)}...`,
        spinner: "dots",
      }).start();

  try {
    const scanner = new Scanner({ verbose: options.verbose });
    const result = await scanner.scan(resolvedTarget);

    if (spinner) {
      spinner.stop();
    }

    if (options.json) {
      const jsonReporter = new JsonReporter();
      const output = jsonReporter.format(result);
      if (options.output) {
        await fs.writeFile(path.resolve(options.output), output, "utf-8");
      } else {
        console.log(output);
      }
      return;
    }

    const terminalReporter = new TerminalReporter();
    const output = terminalReporter.format(result, { verbose: options.verbose });
    console.log(output);

    if (options.output) {
      const jsonReporter = new JsonReporter();
      const jsonOutput = jsonReporter.format(result);
      await fs.writeFile(path.resolve(options.output), jsonOutput, "utf-8");
      console.log(
        chalk.green(`\nReport successfully saved to ${chalk.bold(options.output)}`)
      );
    }

    // Set exit code if critical findings exist (useful for CI future runs)
    if (result.summary.critical > 0) {
      process.exitCode = 1;
    }
  } catch (error) {
    if (spinner) {
      spinner.fail(chalk.red("Scan failed."));
    }
    console.error(
      chalk.red(`\nError executing CERQON scan: ${(error as Error).message}`)
    );
    process.exitCode = 2;
  }
}
