import type { Rule } from "@cerqon/types";

export const cq008UnsafeTransport: Rule = {
  id: "CQ-008", title: "Unsafe Network Transport", severity: "high", category: "network", isImplemented: true,
  description: "Detects unencrypted remote HTTP or WebSocket MCP transport.",
  impact: "Cleartext transport exposes agent traffic to interception or modification.",
  recommendation: "Use encrypted transport; TLS does not establish source trust.",
  evaluate({ config, diagnostics }) {
    return config.servers.filter((s) => {
      if (s.disabled || !s.url) return false;
      let url: URL;
      try { url = new URL(s.url); } catch {
        diagnostics?.push({ code: "CERQON_INVALID_MCP_URL", severity: "warning", message: "MCP server URL is malformed and could not be evaluated.", file: config.sourcePath, adapter: config.adapterName });
        return false;
      }
      const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname.toLowerCase());
      return !local && ["http:", "ws:"].includes(url.protocol);
    }).map((server) => ({
      id: `CQ-008-${server.name}`, ruleId: "CQ-008", title: "Unsafe Network Transport", severity: "high" as const,
      description: "MCP server uses unencrypted HTTP or WebSocket transport.", impact: this.impact, recommendation: this.recommendation,
      location: { file: config.sourcePath }, metadata: { serverName: server.name, url: server.url }, confidence: "confirmed" as const,
    }));
  },
};
