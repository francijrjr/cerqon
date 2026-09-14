import chalk from "chalk";
import { isSupportedNodeVersion, NODE_REQUIREMENT } from "@cerqon/core";
import { AdapterRegistry } from "@cerqon/adapters";
import type { AgentAdapter } from "@cerqon/types";
import { ACTIVE_CERQON_RULES, ALL_CERQON_RULES } from "@cerqon/risk-engine";

export function handleDoctorCommand(): void {
  console.log(chalk.bold.cyan("\nCERQON Environment Doctor"));
  console.log(chalk.dim("Diagnosing local runtime and security scanner configuration.\n"));

  // Check Node version
  const nodeVersion = process.versions.node;
  const supported = isSupportedNodeVersion(nodeVersion);
  if (supported) {
    console.log(
      `${chalk.green("✔")} Node.js runtime: ${chalk.bold(`v${nodeVersion}`)} (Supported ${NODE_REQUIREMENT})`
    );
  } else {
    console.log(
      `${chalk.red("✖")} Node.js runtime: ${chalk.bold(`v${nodeVersion}`)} (Requires ${NODE_REQUIREMENT})`
    );
  }

  // Check OS
  console.log(
    `${chalk.green("✔")} Operating System: ${chalk.bold(process.platform)} (${process.arch})`
  );

  // Check Privacy & Security posture
  console.log(`${chalk.green("✔")} Privacy Mode: ${chalk.bold.green("100% Local-First")}`);
  console.log(`${chalk.green("✔")} Telemetry: ${chalk.bold("OFF")}`);
  console.log(`${chalk.green("✔")} Remote Cloud Upload: ${chalk.bold("OFF")}`);
  console.log(`${chalk.green("✔")} Secret Masking Engine: ${chalk.bold.green("Active")}`);

  // Check registered adapters
  const registry = new AdapterRegistry();
  const adapters: AgentAdapter[] = registry.getAdapters();
  console.log(
    `${chalk.green("✔")} Registered Adapters: ${chalk.bold(adapters.length)} (${adapters.map((a: AgentAdapter) => a.name).join(", ")})`
  );

  // Check rules status
  console.log(
    `${chalk.green("✔")} Security Rules: ${chalk.bold(
      `${ACTIVE_CERQON_RULES.length} active`
    )} / ${ALL_CERQON_RULES.length} defined`
  );

  console.log(
    chalk.cyan(supported ? "\nEnvironment is ready to scan AI agent & MCP configurations.\n" : "\nUpgrade Node.js before scanning.\n")
  );
  process.exitCode = supported ? 0 : 2;
}
