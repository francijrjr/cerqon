import { Command } from "commander";
import { handleScanCommand } from "./commands/scan.js";
import { handleRulesCommand } from "./commands/rules.js";
import { handleDoctorCommand } from "./commands/doctor.js";
import { handleFutureCommand } from "./commands/future.js";

const VERSION = "0.1.0";

const program = new Command();

program
  .name("cerqon")
  .description("CERQON - Security & Control for Autonomous AI")
  .version(VERSION, "-v, --version, version", "Display CERQON version");

program
  .command("scan [path]")
  .description("Scan local AI agent configurations, MCP servers, and tools for security risks")
  .option("-v, --verbose", "Display verbose findings including evidence details")
  .option("--json", "Output scan results in machine-readable JSON")
  .option("-o, --output <file>", "Save scan report to specified file path")
  .action(async (targetPath = ".", options) => {
    await handleScanCommand(targetPath, options);
  });

program
  .command("rules")
  .description("List all CERQON security rules and their operational status")
  .action(() => {
    handleRulesCommand();
  });

program
  .command("doctor")
  .description("Verify local runtime environment, adapters, and privacy posture")
  .action(() => {
    handleDoctorCommand();
  });

// Architecture placeholders for future commands
program
  .command("agents")
  .description("List and inspect configured AI agents [Roadmap 0.2]")
  .action(() => handleFutureCommand("agents", "0.2"));

program
  .command("mcp")
  .description("Manage and audit Model Context Protocol servers [Roadmap 0.2]")
  .action(() => handleFutureCommand("mcp", "0.2"));

program
  .command("secrets")
  .description("Deep-scan environment and config files for leaked agent secrets [Roadmap 0.2]")
  .action(() => handleFutureCommand("secrets", "0.2"));

program
  .command("permissions")
  .description("Inspect effective tool and resource permissions [Roadmap 0.2]")
  .action(() => handleFutureCommand("permissions", "0.2"));

program
  .command("audit")
  .description("Audit agent activity logs and execution traces [Roadmap 0.3]")
  .action(() => handleFutureCommand("audit", "0.3"));

program
  .command("graph")
  .description("Generate and visualize the Agent Capability & Blast Radius Graph [Roadmap 0.3]")
  .action(() => handleFutureCommand("graph", "0.3"));

program
  .command("policy")
  .description("Evaluate and enforce custom security policies as code [Roadmap 0.4]")
  .action(() => handleFutureCommand("policy", "0.4"));

program.parse(process.argv);
