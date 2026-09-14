import { describe, it, expect } from "vitest";
import { cq006UntrustedServer, cq007MissingApproval, cq008UnsafeTransport } from "@cerqon/risk-engine";
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

    expect(cq006UntrustedServer.evaluate({ config })).toHaveLength(0);
    const findings = cq008UnsafeTransport.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-008");
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

    expect(cq006UntrustedServer.evaluate({ config })).toHaveLength(0);
    const findings = cq007MissingApproval.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-007");
    expect(findings[0].description).toContain("wildcard auto-approval");
  });

  it("does not infer source trust from HTTPS or explicit tool approval", () => {
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
