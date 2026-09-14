import { expect, it } from "vitest";
import { ACTIVE_CERQON_RULES, RiskEngine } from "@cerqon/risk-engine";
import type { AgentConfiguration } from "@cerqon/types";

it("does not penalize disabled capabilities in any active rule", () => {
  const config: AgentConfiguration = { id: "x", name: "x", sourcePath: "x", adapterName: "test", servers: [{ name: "shell", command: "bash", rootPaths: ["/"], url: "http://remote.example", autoApprove: ["*"], env: { OPENAI_API_KEY: "sk-proj-abcdefghijklmnopqrstuvw" }, disabled: true }] };
  for (const rule of ACTIVE_CERQON_RULES) expect(rule.evaluate({ config })).toEqual([]);
  expect(new RiskEngine().evaluateAll([config]).scoreResult.score).toBe(100);
  config.servers[0].disabled = false;
  expect(new RiskEngine().evaluateAll([config]).findings.length).toBeGreaterThan(0);
});
