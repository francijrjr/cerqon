import { expect, it } from "vitest";
import { analyzePackageSpec, executionPackageSpecs } from "@cerqon/core";
import { cq006UntrustedServer } from "@cerqon/risk-engine";

it.each(["some-package", "@vendor/mcp-server", "some-package@latest", "some-package@^1.2.0", "some-package@~1.2.0", "some-package@1", "some-package@1.2", "git+https://github.com/org/repo", "github:owner/repo", "https://raw.githubusercontent.com/o/r/main/index.js", "alias@npm:package@latest"])("detects mutable source %s", (spec) => {
  expect(analyzePackageSpec(spec).isMutable).toBe(true);
  expect(cq006UntrustedServer.evaluate({ config: { id: "x", name: "x", sourcePath: "x", adapterName: "test", servers: [{ name: "test", command: "npx", args: ["-y", spec] }] } })).toHaveLength(1);
});
it.each(["some-package@1.2.3", "@vendor/mcp-server@1.5.2", "package@1.2.3-beta.1", "alias@npm:package@1.2.3"])("recognizes exact registry version %s", (spec) => {
  expect(analyzePackageSpec(spec).isExactVersion).toBe(true);
  expect(analyzePackageSpec(spec).isMutable).toBe(false);
});
it("requires a full Git commit and does not accept a tag as immutable", () => {
  expect(analyzePackageSpec("github:owner/repo#" + "a".repeat(40)).isMutable).toBe(false);
  expect(analyzePackageSpec("github:owner/repo#v1.2.3").isMutable).toBe(true);
});
it("does not let a pinned argument hide an unpinned package", () => {
  expect(executionPackageSpecs("npx", ["-y", "@vendor/pkg", "argument@1.2.3"])).toEqual(["@vendor/pkg"]);
  expect(executionPackageSpecs("npx", ["--package", "safe@1.2.3", "--package=unsafe@latest", "tool"])).toEqual(["safe@1.2.3", "unsafe@latest"]);
  expect(executionPackageSpecs("npx", ["safe@1.2.3", "--url", "https://api.example.com"])).toEqual(["safe@1.2.3"]);
  expect(executionPackageSpecs("node", ["app.js"])).toEqual([]);
});
