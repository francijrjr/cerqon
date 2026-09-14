import { describe, it, expect } from "vitest";
import { cq002UnrestrictedFilesystem } from "@cerqon/risk-engine";
import type { AgentConfiguration } from "@cerqon/types";

describe("Rule CQ-002: Unrestricted Filesystem Access", () => {
  it("should flag root '/' filesystem mounts with critical severity", () => {
    const config: AgentConfiguration = {
      id: "agent-1",
      name: "Test Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "filesystem",
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem", "/"],
        },
      ],
    };

    const findings = cq002UnrestrictedFilesystem.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-002");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].metadata?.isRoot).toBe(true);
  });

  it("should flag Windows drive root 'C:\\'", () => {
    const config: AgentConfiguration = {
      id: "agent-win",
      name: "Windows Agent",
      adapterName: "Generic",
      sourcePath: "C:\\test\\mcp.json",
      servers: [
        {
          name: "fs-win",
          rootPaths: ["C:\\"],
        },
      ],
    };

    const findings = cq002UnrestrictedFilesystem.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-002");
    expect(findings[0].severity).toBe("critical");
  });

  it("should flag sensitive system directories such as /etc", () => {
    const config: AgentConfiguration = {
      id: "agent-sys",
      name: "System Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "fs-etc",
          rootPaths: ["/etc"],
        },
      ],
    };

    const findings = cq002UnrestrictedFilesystem.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-002");
  });

  it("should pass safe restricted project paths without findings", () => {
    const config: AgentConfiguration = {
      id: "agent-safe",
      name: "Safe Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "project-fs",
          rootPaths: ["./workspace/data"],
        },
      ],
    };

    const findings = cq002UnrestrictedFilesystem.evaluate({ config });
    expect(findings).toHaveLength(0);
  });
});
