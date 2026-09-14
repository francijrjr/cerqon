import { expect, it } from "vitest";
import { readFileSync } from "node:fs";

it("publishes the alpha version consistently", () => {
  const root = JSON.parse(readFileSync("package.json", "utf8"));
  const cli = JSON.parse(readFileSync("apps/cli/package.json", "utf8"));
  expect(root.version).toBe("0.1.0-alpha.1");
  expect(cli.version).toBe(root.version);
});
