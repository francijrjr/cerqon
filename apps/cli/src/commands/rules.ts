import chalk from "chalk";
import { ALL_CERQON_RULES } from "@cerqon/risk-engine";

export function handleRulesCommand(): void {
  console.log(chalk.bold.cyan("\nCERQON Rules Catalog"));
  console.log(
    chalk.dim("Deterministic security rules for autonomous AI agents and MCP configurations.\n")
  );

  console.log(
    `${chalk.bold("ID".padEnd(8))} ${chalk.bold("STATUS".padEnd(10))} ${chalk.bold(
      "SEVERITY".padEnd(12)
    )} ${chalk.bold("CATEGORY".padEnd(14))} ${chalk.bold("TITLE")}`
  );
  console.log(chalk.dim("─".repeat(78)));

  for (const rule of ALL_CERQON_RULES) {
    const status = rule.isImplemented
      ? chalk.green.bold("ACTIVE".padEnd(10))
      : chalk.yellow("FUTURE".padEnd(10));

    let sevBadge = rule.severity.toUpperCase().padEnd(12);
    if (rule.severity === "critical") sevBadge = chalk.red.bold(sevBadge);
    else if (rule.severity === "high") sevBadge = chalk.hex("#ff8800")(sevBadge);
    else if (rule.severity === "medium") sevBadge = chalk.yellow(sevBadge);
    else if (rule.severity === "low") sevBadge = chalk.blue(sevBadge);

    console.log(
      `${chalk.bold(rule.id.padEnd(8))} ${status} ${sevBadge} ${rule.category.padEnd(
        14
      )} ${chalk.white(rule.title)}`
    );
  }

  console.log(
    chalk.dim("\nUse 'cerqon scan' to evaluate your environment against all active rules.\n")
  );
}
