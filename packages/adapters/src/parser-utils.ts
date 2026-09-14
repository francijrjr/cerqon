import type { MCPServer, MCPTransport } from "@cerqon/types";

export function parseMCPServers(rawServers: unknown): MCPServer[] {
  if (!rawServers || typeof rawServers !== "object") {
    throw new Error("Invalid servers map");
  }
  if (Array.isArray(rawServers)) throw new Error("Invalid servers map");

  const servers: MCPServer[] = [];
  const entries = Object.entries(rawServers as Record<string, unknown>);

  for (const [serverName, rawConfig] of entries) {
    if (!rawConfig || typeof rawConfig !== "object" || Array.isArray(rawConfig)) throw new Error("Invalid server");
    const cfg = rawConfig as Record<string, unknown>;
    for (const field of ["command", "url", "transport"]) {
      if (cfg[field] !== undefined && typeof cfg[field] !== "string") throw new Error("Invalid server string field");
    }
    for (const field of ["args", "autoApprove", "rootPaths"]) {
      const value = cfg[field];
      if (value !== undefined && (!Array.isArray(value) || value.some((v) => typeof v !== "string"))) throw new Error("Invalid server list");
    }
    if (cfg.disabled !== undefined && typeof cfg.disabled !== "boolean") throw new Error("Invalid disabled flag");
    if (cfg.env !== undefined && (!cfg.env || typeof cfg.env !== "object" || Array.isArray(cfg.env) || Object.values(cfg.env).some((v) => typeof v !== "string"))) throw new Error("Invalid environment");
    if (!cfg.command && !cfg.url && !cfg.rootPaths) throw new Error("Missing server source");

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
