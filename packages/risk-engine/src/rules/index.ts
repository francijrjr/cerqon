import type { Rule } from "@cerqon/types";
import { cq002UnrestrictedFilesystem } from "./cq002-filesystem.js";
import { cq003ExposedSecret } from "./cq003-secrets.js";
import { cq005UnsafeShell } from "./cq005-shell.js";
import { cq006UntrustedServer } from "./cq006-untrusted-server.js";
import { futureRules } from "./future-rules.js";
import { cq007MissingApproval } from "./cq007-approval.js";
import { cq008UnsafeTransport } from "./cq008-transport.js";
import { cq001ExcessiveToolPermission } from "./cq001-permissions.js";
export * from "./cq001-permissions.js";
export * from "./cq007-approval.js";
export * from "./cq008-transport.js";

export * from "./cq002-filesystem.js";
export * from "./cq003-secrets.js";
export * from "./cq005-shell.js";
export * from "./cq006-untrusted-server.js";
export * from "./future-rules.js";

export const ALL_CERQON_RULES: Rule[] = [
  // CQ-001
  cq001ExcessiveToolPermission,
  // CQ-002 (Active)
  cq002UnrestrictedFilesystem,
  // CQ-003 (Active)
  cq003ExposedSecret,
  // CQ-004
  futureRules.find((r) => r.id === "CQ-004")!,
  // CQ-005 (Active)
  cq005UnsafeShell,
  // CQ-006 (Active)
  cq006UntrustedServer,
  // CQ-007 through CQ-012
  cq007MissingApproval,
  cq008UnsafeTransport,
  futureRules.find((r) => r.id === "CQ-009")!,
  futureRules.find((r) => r.id === "CQ-010")!,
  futureRules.find((r) => r.id === "CQ-011")!,
  futureRules.find((r) => r.id === "CQ-012")!,
];

export const ACTIVE_CERQON_RULES: Rule[] = ALL_CERQON_RULES.filter(
  (r) => r.isImplemented
);
