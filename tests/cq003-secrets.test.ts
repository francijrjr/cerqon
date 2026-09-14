import { describe, it, expect } from "vitest";
import { cq003ExposedSecret } from "@cerqon/risk-engine";
import type { AgentConfiguration } from "@cerqon/types";

describe("Rule CQ-003: Exposed Agent Secret", () => {
  it("should detect and safely mask OpenAI API keys", () => {
    const rawSecret = "sk-proj-1234567890abcdef1234567890abcdef";
    const config: AgentConfiguration = {
      id: "agent-secret",
      name: "Secret Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "llm-server",
          env: {
            OPENAI_API_KEY: rawSecret,
          },
        },
      ],
    };

    const findings = cq003ExposedSecret.evaluate({ config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("CQ-003");
    expect(findings[0].severity).toBe("critical");

    // Ensure raw secret is NEVER exposed in evidence, description, or metadata
    expect(findings[0].description).not.toContain(rawSecret);
    expect(findings[0].evidence).not.toContain(rawSecret);
    expect(findings[0].description).toContain("sk-proj-****...****");
    expect(findings[0].metadata?.maskedValue).toBe("sk-proj-****...****");
  });

  it("should detect AWS Access Keys and Database connection strings", () => {
    const config: AgentConfiguration = {
      id: "agent-aws",
      name: "Cloud Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "cloud-server",
          env: {
            AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
            DATABASE_URL: "postgresql://user:secretpw@db.cloud.com:5432/main",
          },
        },
      ],
    };

    const findings = cq003ExposedSecret.evaluate({ config });
    expect(findings).toHaveLength(2);
    for (const f of findings) {
      expect(f.severity).toBe("critical");
      expect(f.ruleId).toBe("CQ-003");
      expect(f.description).toContain("****");
    }
  });

  it("should ignore safe environment variable references like ${VAR}", () => {
    const config: AgentConfiguration = {
      id: "agent-env-ref",
      name: "Safe Env Agent",
      adapterName: "Generic",
      sourcePath: "/test/mcp.json",
      servers: [
        {
          name: "safe-server",
          env: {
            OPENAI_API_KEY: "${OPENAI_API_KEY}",
            ANTHROPIC_API_KEY: "$ANTHROPIC_API_KEY",
          },
        },
      ],
    };

    const findings = cq003ExposedSecret.evaluate({ config });
    expect(findings).toHaveLength(0);
  });
});
