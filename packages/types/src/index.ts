export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type RuleCategory =
  | "filesystem"
  | "secrets"
  | "execution"
  | "network"
  | "permissions"
  | "governance"
  | "supply-chain"
  | "correlation";

export interface FindingLocation {
  file?: string;
  line?: number;
  column?: number;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  location?: FindingLocation;
  evidence?: string;
  impact: string;
  recommendation: string;
  metadata?: Record<string, unknown>;
  confidence?: "confirmed" | "likely" | "heuristic";
  fingerprint?: string;
}

export type MCPTransport = "stdio" | "http" | "sse" | "unknown";

export interface MCPServer {
  name: string;
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  transport?: MCPTransport;
  disabled?: boolean;
  autoApprove?: string[];
  rootPaths?: string[];
  metadata?: Record<string, unknown>;
}

export interface AgentTool {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
  permissions?: string[];
}

export interface AgentConfiguration {
  id: string;
  name: string;
  adapterName: string;
  sourcePath: string;
  servers: MCPServer[];
  tools?: AgentTool[];
  envVars?: Record<string, string>;
  metadata?: Record<string, unknown>;
}

export interface RuleContext {
  config: AgentConfiguration;
  allConfigs?: AgentConfiguration[];
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: RuleCategory;
  isImplemented: boolean;
  impact: string;
  recommendation: string;
  references?: string[];
  evaluate: (context: RuleContext) => Finding[];
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  totalFindings: number;
}

export interface EnvironmentStats {
  agents: number;
  mcpServers: number;
  tools: number;
  integrations: number;
}

export interface ScanResult {
  schemaVersion: "1";
  scanStatus: "complete" | "partial" | "failed";
  diagnostics: ScanDiagnostic[];
  cerqonVersion: string;
  timestamp: string;
  targetPath: string;
  score: number | null;
  summary: ScanSummary;
  environment: EnvironmentStats;
  findings: Finding[];
  durationMs: number;
}

export interface AgentAdapter {
  name: string;
  detect(targetDir: string): Promise<boolean>;
  discover(targetDir: string, diagnostics?: ScanDiagnostic[]): Promise<AgentConfiguration[]>;
  scan?(config: AgentConfiguration): Promise<Finding[]>;
}

export interface ScanDiagnostic {
  code: string;
  severity: "warning" | "error";
  message: string;
  file?: string;
  adapter?: string;
}
