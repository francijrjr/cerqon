import chalk from "chalk";
import type { Finding, ScanResult, Severity } from "@cerqon/types";

export interface TerminalReporterOptions {
  verbose?: boolean;
}

export class TerminalReporter {
  format(result: ScanResult, options: TerminalReporterOptions = {}): string {
    const lines: string[] = [];

    // Header banner
    lines.push(chalk.bold.cyan("CERQON"));
    lines.push(chalk.dim("AI Agent Security Scanner\n"));

    // Environment section
    lines.push(chalk.bold("Environment"));
    lines.push(chalk.dim("────────────────────────────────"));
    lines.push(
      `${"Agents".padEnd(24)} ${chalk.bold(result.environment.agents)}`
    );
    lines.push(
      `${"MCP Servers".padEnd(24)} ${chalk.bold(result.environment.mcpServers)}`
    );
    lines.push(
      `${"Tools".padEnd(24)} ${chalk.bold(result.environment.tools)}`
    );
    lines.push(
      `${"Integrations".padEnd(24)} ${chalk.bold(result.environment.integrations)}\n`
    );

    // Security Score section
    lines.push(chalk.bold("Security Score"));
    lines.push(chalk.dim("────────────────────────────────"));
    const scoreColor =
      result.score >= 80
        ? chalk.bold.green
        : result.score >= 50
        ? chalk.bold.yellow
        : chalk.bold.red;

    lines.push(`${scoreColor(`${result.score} / 100`)}\n`);

    lines.push(
      `${chalk.bold.red("CRITICAL").padEnd(33)} ${result.summary.critical}`
    );
    lines.push(
      `${chalk.bold.hex("#ff8800")("HIGH").padEnd(33)} ${result.summary.high}`
    );
    lines.push(
      `${chalk.bold.yellow("MEDIUM").padEnd(33)} ${result.summary.medium}`
    );
    lines.push(
      `${chalk.bold.blue("LOW").padEnd(33)} ${result.summary.low}\n`
    );

    // Findings section
    if (result.findings.length === 0) {
      lines.push(chalk.bold.green("No security findings detected.\n"));
      return lines.join("\n");
    }

    lines.push(chalk.bold("Findings"));
    lines.push(chalk.dim("────────────────────────────────\n"));

    for (const finding of result.findings) {
      lines.push(this.formatFinding(finding, options.verbose));
      lines.push("");
    }

    return lines.join("\n");
  }

  private formatFinding(finding: Finding, verbose = false): string {
    const lines: string[] = [];

    const sevBadge = this.formatSeverity(finding.severity);
    lines.push(chalk.bold(finding.ruleId));
    lines.push(sevBadge);
    lines.push("");
    lines.push(chalk.bold.white(finding.title));
    lines.push("");

    if (finding.metadata?.agentName) {
      lines.push(chalk.dim("Agent:"));
      lines.push(String(finding.metadata.agentName));
      lines.push("");
    }

    if (finding.metadata?.serverName) {
      lines.push(chalk.dim("MCP:"));
      lines.push(String(finding.metadata.serverName));
      lines.push("");
    }

    if (finding.metadata?.targetPath) {
      lines.push(chalk.dim("Path:"));
      lines.push(chalk.yellow(String(finding.metadata.targetPath)));
      lines.push("");
    }

    if (finding.metadata?.toolName) {
      lines.push(chalk.dim("Tool:"));
      lines.push(String(finding.metadata.toolName));
      lines.push("");
    }

    const shellCap = finding.metadata?.shellType || finding.metadata?.capability;
    if (shellCap) {
      lines.push(chalk.dim("Capability:"));
      lines.push(String(shellCap));
      lines.push("");
    }

    if (finding.metadata?.maskedValue) {
      lines.push(chalk.dim("Secret:"));
      lines.push(chalk.yellow(`${finding.metadata.key}=${finding.metadata.maskedValue}`));
      lines.push("");
    }

    if (finding.metadata?.url) {
      lines.push(chalk.dim("URL:"));
      lines.push(chalk.yellow(String(finding.metadata.url)));
      lines.push("");
    }

    if (finding.location?.file && verbose) {
      lines.push(chalk.dim("Location:"));
      lines.push(finding.location.file);
      lines.push("");
    }

    if (finding.evidence && verbose) {
      lines.push(chalk.dim("Evidence:"));
      lines.push(finding.evidence);
      lines.push("");
    }

    lines.push(chalk.dim("Impact:"));
    lines.push(finding.impact);
    lines.push("");

    lines.push(chalk.dim("Recommendation:"));
    lines.push(chalk.cyan(finding.recommendation));

    return lines.join("\n");
  }

  private formatSeverity(severity: Severity): string {
    switch (severity) {
      case "critical":
        return chalk.bgRed.black.bold(" CRITICAL ");
      case "high":
        return chalk.bgHex("#ff8800").black.bold(" HIGH ");
      case "medium":
        return chalk.bgYellow.black.bold(" MEDIUM ");
      case "low":
        return chalk.bgBlue.white.bold(" LOW ");
      case "info":
        return chalk.bgGray.white.bold(" INFO ");
      default:
        return severity;
    }
  }
}
