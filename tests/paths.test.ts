import { expect, it } from "vitest";
import { assessPathSafety } from "@cerqon/core";

it.each(["/", "C:\\", "D:/", "/root", "/root/.ssh", "/home/john/.ssh", "C:\\Users\\john\\.aws"])("classifies critical credential/root scope %s", (value) => {
  expect(assessPathSafety(value).riskLevel).toBe("critical");
});
it.each(["/etc", "/etc/ssh", "/usr", "/var", "/home", "~/", "C:\\Windows", "C:\\Windows\\System32", "C:\\Users", "C:\\Program Files", "/workspace/../etc"])("classifies high system scope %s", (value) => {
  expect(assessPathSafety(value).riskLevel).toBe("high");
});
it.each(["/home/john", "C:\\Users\\john"])("marks individual home scope for contextual review %s", (value) => {
  expect(assessPathSafety(value).riskLevel).toBe("medium");
});
it.each(["./src", "./workspace/data", "/workspace/project", "C:\\projects\\cerqon", "/etcetera", "/home/john/project", "C:\\WindowsProject", "/Root", "./etc"])("avoids project-path false positives %s", (value) => {
  expect(assessPathSafety(value).riskLevel).toBe("safe");
});
