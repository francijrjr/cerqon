import chalk from "chalk";

export function handleFutureCommand(commandName: string, milestone: string): void {
  console.log(chalk.bold.cyan(`\nCERQON ${commandName.toUpperCase()}`));
  console.log(
    chalk.yellow(`Command 'cerqon ${commandName}' is scheduled for Milestone ${milestone}.`)
  );
  console.log(
    chalk.dim(`Track upcoming progress and architecture at: https://github.com/cerqon-security/cerqon\n`)
  );
}
