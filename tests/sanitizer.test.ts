import { expect, it } from "vitest";
import { sanitizeUnknownValue, sanitizeFinding, collectSecretValues } from "@cerqon/core";
import { RiskEngine } from "@cerqon/risk-engine";

it("redacts nested metadata, URL credentials, tokens and command flags without mutation", () => {
  const raw = "ghp_abcdefghijklmnopqrstuvwxyz";
  const source = { url: "https://john:supersecret@example.com", metadata: { nested: [raw, { password: "abc123" }] }, args: ["--api-key", "arbitraryKey123"], privateKey: "-----BEGIN PRIVATE KEY-----\nsecretBody\n-----END PRIVATE KEY-----" };
  const output = JSON.stringify(sanitizeUnknownValue(source));
  for (const secret of [raw, "supersecret", "john", "abc123", "arbitraryKey123", "secretBody"]) expect(output).not.toContain(secret);
  expect(source.metadata.nested[0]).toBe(raw);
});

it("removes contextual secrets even from finding identifiers and metadata keys", () => {
  const raw = "plaintextSecret987";
  const finding = { id: raw, ruleId: "test", title: "test", description: raw, severity: "high" as const, impact: raw, recommendation: raw, metadata: { [raw]: [raw] } };
  const secrets = collectSecretValues({ env: { AWS_SECRET_ACCESS_KEY: raw } });
  expect(JSON.stringify(sanitizeFinding(finding, secrets))).not.toContain(raw);
});

it("sanitizes findings emitted by rules other than CQ-003", () => {
  const result = new RiskEngine().evaluateAll([{ id: "x", name: "x", sourcePath: "/test.json", adapterName: "test", servers: [{ name: "remote", url: "http://user:supersecret@example.com", command: "npx", args: ["git+https://ghp_abcdefghijklmnopqrstuvwxyz@github.com/org/repo"] }] }]);
  expect(JSON.stringify(result)).not.toContain("supersecret");
  expect(JSON.stringify(result)).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz");
});
