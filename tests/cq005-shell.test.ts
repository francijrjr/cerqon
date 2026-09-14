import { describe, it, expect } from "vitest";
import { cq005UnsafeShell } from "@cerqon/risk-engine";
import type { AgentConfiguration } from "@cerqon/types";

describe("Rule CQ-005: Unsafe Shell Capability", () => {
  it("should flag MCP server commands invoking bash or powershell", () => {
    const config: AgentConfiguration = {
      id: "agent-shell",
      name: "Shell Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "term-runner",
          command: "powershell.exe",
          args: ["-Command"],
        },
      ],
    };

    const findings = cq005UnsafeShell.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-005");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].metadata?.shellType).toBe("powershell.exe");
  });

  it("should flag agent tools with execution keywords", () => {
    const config: AgentConfiguration = {
      id: "agent-tool-exec",
      name: "Exec Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [],
      tools: [
        {
          name: "execute_command",
          description: "Runs arbitrary shell command",
        },
        {
          name: "read_file",
          description: "Reads file content safely",
        },
      ],
    };

    const findings = cq005UnsafeShell.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-005");
    expect(findings[0].metadata?.toolName).toBe("execute_command");
  });

  it("should pass benign tools without shell capabilities", () => {
    const config: AgentConfiguration = {
      id: "agent-benign",
      name: "Benign Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "calculator",
          command: "node",
          args: ["calc.js"],
        },
      ],
      tools: [
        {
          name: "add_numbers",
        },
      ],
    };

    const findings = cq005UnsafeShell.evaluate({ config });
    expect(findings).toHaveLength(0);
  });
});
