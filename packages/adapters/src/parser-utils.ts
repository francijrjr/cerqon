import type { MCPServer, MCPTransport } from "@cerqon/types";

export function parseMCPServers(rawServers: unknown): MCPServer[] {
  if (!rawServers || typeof rawServers !== "object") {
    return [];
  }

  const servers: MCPServer[] = [];
  const entries = Object.entries(rawServers as Record<string, unknown>);

  for (const [serverName, rawConfig] of entries) {
    if (!rawConfig || typeof rawConfig !== "object") continue;
    const cfg = rawConfig as Record<string, unknown>;

    let transport: MCPTransport = "unknown";
    if (cfg.transport === "stdio" || cfg.transport === "http" || cfg.transport === "sse") {
      transport = cfg.transport;
    } else if (cfg.command) {
      transport = "stdio";
    } else if (typeof cfg.url === "string") {
      transport = cfg.url.includes("/sse") ? "sse" : "http";
    }

    const command = typeof cfg.command === "string" ? cfg.command : undefined;
    const args = Array.isArray(cfg.args)
      ? cfg.args.filter((a): a is string => typeof a === "string")
      : undefined;
    const url = typeof cfg.url === "string" ? cfg.url : undefined;
    const env =
      cfg.env && typeof cfg.env === "object"
        ? (cfg.env as Record<string, string>)
        : undefined;
    const disabled = typeof cfg.disabled === "boolean" ? cfg.disabled : false;
    const autoApprove = Array.isArray(cfg.autoApprove)
      ? cfg.autoApprove.filter((a): a is string => typeof a === "string")
      : undefined;

    // Detect rootPaths if passed explicitly or extracted from args (e.g. server-filesystem <path>)
    const rootPaths: string[] = [];
    if (Array.isArray(cfg.rootPaths)) {
      for (const p of cfg.rootPaths) {
        if (typeof p === "string") rootPaths.push(p);
      }
    }

    // Extract filesystem paths from server-filesystem args
    if (args && args.length > 0) {
      const isFsServer =
        serverName.toLowerCase().includes("filesystem") ||
        args.some((a) => a.includes("server-filesystem"));
      if (isFsServer) {
        for (const arg of args) {
          // Avoid flags
          if (!arg.startsWith("-") && !arg.includes("server-filesystem")) {
            rootPaths.push(arg);
          }
        }
      }
    }

    servers.push({
      name: serverName,
      command,
      args,
      url,
      env,
      transport,
      disabled,
      autoApprove,
      rootPaths: rootPaths.length > 0 ? rootPaths : undefined,
    });
  }

  return servers;
}
