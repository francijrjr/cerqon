import { expect, it } from "vitest";
import { cq003ExposedSecret } from "@cerqon/risk-engine";

it("detects credential patterns in URLs, args and nested metadata without raw output", () => {
  const raw = "ghp_abcdefghijklmnopqrstuvwxyz";
  const config = { id: "x", name: "x", sourcePath: "x", adapterName: "test", metadata: { token: raw }, servers: [{ name: "remote", url: `https://${raw}@github.com/org/repo`, args: ["--token", raw], metadata: { nested: raw } }] };
  const findings = cq003ExposedSecret.evaluate({ config });
  expect(findings.length).toBeGreaterThan(0);
  expect(JSON.stringify(findings)).not.toContain(raw);
});
