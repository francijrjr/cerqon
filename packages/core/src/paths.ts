import path from "node:path";

export interface PathSafetyAssessment {
  isDangerous: boolean;
  isRoot: boolean;
  riskLevel: "critical" | "high" | "medium" | "safe";
  reason?: string;
  normalizedPath: string;
}

/** Lexical classification is platform independent; it cannot resolve symlinks or ACLs. */
export function assessPathSafety(targetPath: string): PathSafetyAssessment {
  const input = targetPath.trim();
  const windows = /^[a-z]:/i.test(input) || input.startsWith("\\\\");
  const normalized = windows ? path.win32.normalize(input).replace(/\\/g, "/").toLowerCase()
    : path.posix.normalize(input.replace(/\\/g, "/"));
  const value = normalized.replace(/\/$/, "") || "/";
  const result = (riskLevel: PathSafetyAssessment["riskLevel"], reason?: string, isRoot = false): PathSafetyAssessment =>
    ({ isDangerous: riskLevel !== "safe", isRoot, riskLevel, reason, normalizedPath: normalized });
  if (!input) return result("safe");
  if (value === "/" || /^[a-z]:$/i.test(value) || (windows && /^\/\/[^/]+\/[^/]+$/.test(value))) {
    return result("critical", "Filesystem or volume root grants broad host access.", true);
  }
  const within = (root: string) => value === root || value.startsWith(root + "/");
  if (within("/root") || /(?:^|\/)\.(?:ssh|aws|gnupg)(?:\/|$)/.test(value)) {
    return result("critical", "Path exposes privileged home or credential directories.");
  }
  const systemRoots = windows
    ? ["/windows", "/program files", "/program files (x86)", "/programdata"].map((root) => value.slice(0, 2) + root)
    : ["/etc", "/usr", "/var", "/bin", "/sbin"];
  if (systemRoots.some(within) || ["/home", "/users", "~"].includes(value) || /^[a-z]:\/users$/.test(value)) {
    return result("high", "Broad system or shared home directory is exposed.");
  }
  if (/^\/(?:home|users)\/[^/]+$/.test(value) || /^[a-z]:\/users\/[^/]+$/.test(value) || value === ".." || value.startsWith("../")) {
    return result("medium", "User-wide or parent-directory scope requires review against intended project boundaries.");
  }
  return result("safe");
}
