import { describe, it, expect } from "vitest";
import { cq006UntrustedServer } from "@cerqon/risk-engine";
import type { AgentConfiguration } from "@cerqon/types";

describe("Rule CQ-006: Untrusted MCP Server", () => {
  it("should flag remote MCP endpoints over unencrypted HTTP", () => {
    const config: AgentConfiguration = {
      id: "agent-http",
      name: "Remote Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "remote-insecure",
          url: "http://api.remote-mcp.internal:8080/sse",
        },
      ],
    };

    const findings = cq006UntrustedServer.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-006");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].description).toContain("unencrypted HTTP");
  });

  it("should flag wildcard auto-approval configurations", () => {
    const config: AgentConfiguration = {
      id: "agent-auto",
      name: "Wildcard Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "auto-server",
          autoApprove: ["*"],
        },
      ],
    };

    const findings = cq006UntrustedServer.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-006");
    expect(findings[0].description).toContain("wildcard auto-approval");
  });

  it("should pass secure HTTPS endpoints and explicit auto-approval", () => {
    const config: AgentConfiguration = {
      id: "agent-secure",
      name: "TLS Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "secure-mcp",
          url: "https://mcp.trusted.com/sse",
          autoApprove: ["get_weather"],
        },
      ],
    };

    const findings = cq006UntrustedServer.evaluate({ config });
    expect(findings).toHaveLength(0);
  });
});
