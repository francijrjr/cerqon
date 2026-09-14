
export interface PathSafetyAssessment {
  isDangerous: boolean;
  isRoot: boolean;
  reason?: string;
  normalizedPath: string;
}

const SYSTEM_ROOTS = new Set([
  "/",
  "\\",
  "c:\\",
  "c:/",
  "d:\\",
  "d:/",
  "e:\\",
  "e:/",
]);

const SENSITIVE_SYSTEM_PREFIXES = [
  "/etc",
  "/var",
  "/root",
  "/usr",
  "/bin",
  "/sbin",
  "c:\\windows",
  "c:\\program files",
  "c:\\program files (x86)",
  "c:\\users",
  "/users",
  "/home",
];

export function assessPathSafety(targetPath: string): PathSafetyAssessment {
  if (!targetPath || typeof targetPath !== "string") {
    return { isDangerous: false, isRoot: false, normalizedPath: "" };
  }

  const trimmed = targetPath.trim();
  const lower = trimmed.toLowerCase();

  // Check if exactly root
  if (SYSTEM_ROOTS.has(lower) || lower === "/") {
    return {
      isDangerous: true,
      isRoot: true,
      reason: "Root directory mount allows full access to the entire host filesystem.",
      normalizedPath: trimmed,
    };
  }

  // Windows drive root (e.g. C:, C:\, C:/)
  if (/^[a-zA-Z]:[\\/]?$/.test(trimmed)) {
    return {
      isDangerous: true,
      isRoot: true,
      reason: "Drive root access grants unconstrained file modification across the entire storage volume.",
      normalizedPath: trimmed,
    };
  }

  // Check sensitive system directories
  const normalizedForward = trimmed.replace(/\\/g, "/").toLowerCase();
  for (const sysPrefix of SENSITIVE_SYSTEM_PREFIXES) {
    const sysForward = sysPrefix.replace(/\\/g, "/").toLowerCase();
    if (
      normalizedForward === sysForward ||
      normalizedForward === sysForward + "/"
    ) {
      return {
        isDangerous: true,
        isRoot: false,
        reason: `Access to broad system or user directory '${trimmed}' compromises host isolation.`,
        normalizedPath: trimmed,
      };
    }
  }

  // Check home directory alias
  if (trimmed === "~" || trimmed === "~/" || trimmed === "~\\") {
    return {
      isDangerous: true,
      isRoot: false,
      reason: "Home directory mount exposes user credentials, SSH keys, and all personal documents.",
      normalizedPath: trimmed,
    };
  }

  return {
    isDangerous: false,
    isRoot: false,
    normalizedPath: trimmed,
  };
}
