import { expect, it } from "vitest";
import fs from "node:fs";
import { isSupportedNodeVersion, NODE_REQUIREMENT } from "@cerqon/core";

it.each([["18.20.0", false], ["20.0.0", false], ["20.18.9", false], ["20.19.0", true], ["22.0.0", true], ["invalid", false]])("checks Node %s using semantic versions", (version, expected) => {
  expect(isSupportedNodeVersion(String(version))).toBe(expected);
});
it("keeps the root engine requirement aligned with doctor", () => {
  expect(JSON.parse(fs.readFileSync("package.json", "utf8")).engines.node).toBe(NODE_REQUIREMENT);
});
