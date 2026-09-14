export const KNOWN_SHELL_BINARIES = new Set([
  "bash",
  "bash.exe",
  "sh",
  "sh.exe",
  "zsh",
  "zsh.exe",
  "cmd",
  "cmd.exe",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
  "wsl",
  "wsl.exe",
]);

export const SHELL_KEYWORDS = [
  "exec",
  "spawn",
  "shell",
  "terminal",
  "command-line",
  "run_command",
  "execute_command",
];

export interface ShellCapabilityCheck {
  hasShellCapability: boolean;
  shellType?: string;
  matchedTerm?: string;
  reason?: string;
}

export function detectShellCapability(
  command?: string,
  args?: string[],
  toolName?: string
): ShellCapabilityCheck {
  // Check command binary
  if (command) {
    const cmdLower = command.toLowerCase().replace(/\\/g, "/");
    const binary = cmdLower.split("/").pop() || "";
    if (KNOWN_SHELL_BINARIES.has(binary)) {
      return {
        hasShellCapability: true,
        shellType: binary,
        matchedTerm: binary,
        reason: `Command directly invokes shell binary '${binary}'`,
      };
    }

    for (const kw of SHELL_KEYWORDS) {
      if (binary.includes(kw)) {
        return {
          hasShellCapability: true,
          shellType: binary,
          matchedTerm: kw,
          reason: `Command name contains shell execution keyword '${kw}'`,
        };
      }
    }
  }

  // Check arguments
  if (args && args.length > 0) {
    for (const arg of args) {
      const argLower = arg.toLowerCase().replace(/\\/g, "/");
      const argBase = argLower.split("/").pop() || "";
      if (KNOWN_SHELL_BINARIES.has(argBase)) {
        return {
          hasShellCapability: true,
          shellType: argBase,
          matchedTerm: argBase,
          reason: `Command argument references shell executable '${argBase}'`,
        };
      }
    }
  }

  // Check tool name
  if (toolName) {
    const toolLower = toolName.toLowerCase();
    for (const kw of [...KNOWN_SHELL_BINARIES, ...SHELL_KEYWORDS]) {
      if (toolLower === kw || toolLower.includes(kw)) {
        return {
          hasShellCapability: true,
          shellType: kw,
          matchedTerm: kw,
          reason: `Tool '${toolName}' indicates arbitrary shell or command execution capability`,
        };
      }
    }
  }

  return {
    hasShellCapability: false,
  };
}
