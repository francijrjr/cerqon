import { expect, it } from "vitest";
import { cq003ExposedSecret } from "@cerqon/risk-engine";
function check(value: string, key = "TOKEN") {
  return cq003ExposedSecret.evaluate({ config: { id: "x", name: "x", sourcePath: "x", adapterName: "test", servers: [{ name: "x", env: { [key]: value } }] } });
}
it.each([
  "sk-proj-" + "a".repeat(30), "sk-ant-" + "b".repeat(30), "AKIAIOSFODNN7EXAMPLE",
  "ghp_abcdefghijklmnopqrstuvwxyz", "xoxb-" + "a".repeat(20), "-----BEGIN PRIVATE KEY-----",
  "postgresql://admin:password@prod.example.com/db", "mysql://u:p@host/db", "mongodb+srv://u:p@host/db", "redis://:password@host/0",
])("confirms recognized patterns and never emits the raw value: %s", (value) => {
  const findings = check(value);
  expect(findings[0].confidence).toBe("confirmed");
  expect(JSON.stringify(findings)).not.toContain(value);
});
it("uses likely rather than confirmed for a sensitive variable with plaintext", () => {
  const raw = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  const findings = check(raw, "AWS_SECRET_ACCESS_KEY");
  expect(findings[0].confidence).toBe("likely");
  expect(findings[0].severity).toBe("high");
  expect(JSON.stringify(findings)).not.toContain(raw);
});
it.each(["${OPENAI_API_KEY}", "$OPENAI_API_KEY", "<YOUR_KEY>", "false", "postgresql://localhost/db"])("ignores non-credential values %s", (value) => {
  expect(check(value, "DATABASE_URL")).toHaveLength(0);
});
it("does not let reference-like prefixes suppress an embedded known token", () => {
  expect(check("$not_a_reference ghp_abcdefghijklmnopqrstuvwxyz")).toHaveLength(1);
});
