import { expect, it } from "vitest";
import fs from "node:fs";

it("defines a composite action using the bundled CLI and safe inputs", () => {
  const action = fs.readFileSync("action.yml", "utf8");
  expect(action).toContain("using: composite"); expect(action).toContain("apps/cli/dist/index.js");
  expect(action).toContain("fail-on"); expect(action).toContain("format");
});
