import type { Rule } from "@cerqon/types";

export const futureRules: Rule[] = [
  {
    id: "CQ-001",
    title: "Excessive Tool Permission",
    description:
      "Detects tools configured with wildcard or overly broad action permissions that exceed operational necessity.",
    severity: "high",
    category: "permissions",
    isImplemented: false,
    impact:
      "Excessive tool capabilities allow an agent to perform actions beyond its designated scope if prompt boundaries fail.",
    recommendation:
      "Apply the principle of least privilege by scoping tool permissions to explicit read/write subsets.",
    references: ["https://cwe.mitre.org/data/definitions/250.html"],
    evaluate: () => [],
  },
  {
    id: "CQ-004",
    title: "Excessive OAuth Scope",
    description:
      "Flags external integrations requesting administrative or unrestricted OAuth scopes.",
    severity: "medium",
    category: "permissions",
    isImplemented: false,
    impact:
      "Overly broad OAuth tokens grant AI agents full tenancy access across third-party SaaS services.",
    recommendation:
      "Restrict requested OAuth scopes strictly to resource-level read or scoped write permissions.",
    references: ["https://oauth.net/2/scope/"],
    evaluate: () => [],
  },
  {
    id: "CQ-007",
    title: "Missing Human Approval",
    description:
      "Checks whether destructive or external write actions mandate human-in-the-loop confirmation.",
    severity: "medium",
    category: "governance",
    isImplemented: false,
    impact:
      "Unsupervised execution of high-impact mutations can cause irreversible data deletion or deployment outages.",
    recommendation:
      "Enforce explicit approval gates on destructive and outbound actions.",
    references: ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    evaluate: () => [],
  },
  {
    id: "CQ-008",
    title: "Agent Network Exposure",
    description:
      "Identifies agent listeners or MCP servers exposed directly to unauthenticated external network interfaces.",
    severity: "high",
    category: "network",
    isImplemented: false,
    impact:
      "Exposing agent endpoints to 0.0.0.0 without authentication allows remote adversaries to issue malicious prompt requests.",
    recommendation:
      "Bind agent listeners to localhost (127.0.0.1) or require mutual TLS / bearer token authentication.",
    references: ["https://cwe.mitre.org/data/definitions/306.html"],
    evaluate: () => [],
  },
  {
    id: "CQ-009",
    title: "Tool Definition Drift",
    description:
      "Detects discrepancy between locally registered tool schemas and trusted registry hashes.",
    severity: "low",
    category: "supply-chain",
    isImplemented: false,
    impact:
      "Drifting tool implementations might include unauthorized schema changes or compromised third-party code.",
    recommendation:
      "Lock tool manifests to cryptographic checksums verified against a central policy repository.",
    references: ["https://slsa.dev/"],
    evaluate: () => [],
  },
  {
    id: "CQ-010",
    title: "Missing Audit Trail",
    description:
      "Flags configurations where execution logging, prompt history, or audit traces are disabled.",
    severity: "low",
    category: "governance",
    isImplemented: false,
    impact:
      "Absence of audit records prevents forensic investigation and post-incident attribution.",
    recommendation:
      "Enable centralized, immutable logging for all agent tool invocations and state changes.",
    references: ["https://cwe.mitre.org/data/definitions/778.html"],
    evaluate: () => [],
  },
  {
    id: "CQ-011",
    title: "Cross-Agent Data Exposure",
    description:
      "Identifies shared working directories or memory stores between agents with disparate privilege levels.",
    severity: "high",
    category: "correlation",
    isImplemented: false,
    impact:
      "A lower-privilege agent may access or tamper with sensitive data belonging to a higher-privilege agent.",
    recommendation:
      "Isolate workspace directories and state stores per agent identity.",
    references: ["https://cwe.mitre.org/data/definitions/668.html"],
    evaluate: () => [],
  },
  {
    id: "CQ-012",
    title: "Dangerous Capability Chain",
    description:
      "Detects toxic combinations of capabilities (e.g., Filesystem Read + Secret Access + Outbound Shell/Network).",
    severity: "critical",
    category: "correlation",
    isImplemented: false,
    impact:
      "Even if individual tools appear safe, chained together they form an autonomous exfiltration or remote exploit pipeline.",
    recommendation:
      "Enforce composite capability boundaries preventing simultaneous possession of read-sensitive and outbound-transmission privileges.",
    references: ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    evaluate: () => [],
  },
];
