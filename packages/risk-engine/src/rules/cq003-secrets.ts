import type { Finding, Rule, RuleContext } from "@cerqon/types";
import {
  isSensitiveKeyName,
  KNOWN_SECRET_PATTERNS,
  maskSecret,
  isSecretReference,
  sanitizeFinding,
} from "@cerqon/core";

export const cq003ExposedSecret: Rule = {
  id: "CQ-003",
  title: "Exposed Agent Secret",
  description:
    "Detects hardcoded API keys, tokens, or credentials stored directly inside agent configuration files or environment blocks.",
  severity: "critical",
  category: "secrets",
  isImplemented: true,
  impact:
    "Credentials stored in plaintext may be exfiltrated if the agent configuration is compromised, logged, or shared across version control.",
  recommendation:
    "Do not commit secrets in configuration files. Inject credentials via runtime environment variables or a secure secret manager.",
  references: [
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
  ],
  evaluate(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { config } = context;

    const checkEnvBlock = (
      envObj: Record<string, string> | undefined,
      serverName?: string
    ) => {
      if (!envObj || typeof envObj !== "object") return;

      for (const [key, val] of Object.entries(envObj)) {
        if (typeof val !== "string") continue;

        // Skip placeholders like ${ENV_VAR} or <YOUR_KEY> or empty strings
        const isPlaceholder =
          isSecretReference(val) ||
          val.trim() === "";
        if (isPlaceholder) continue;

        let detectedSecret = false;
        let matchedPatternName = "";
        let confidence: "confirmed" | "likely" | "heuristic" = "confirmed";

        // 1. Check against known secret regexes
        for (const pattern of KNOWN_SECRET_PATTERNS) {
          if (pattern.regex.test(val)) {
            detectedSecret = true;
            matchedPatternName = pattern.name;
            break;
          }
        }

        // 2. Check if key name indicates a sensitive secret and value has meaningful length
        const credentialFreeUrl = /^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\//i.test(val) && !val.includes("@");
        const nonSecretLiteral = /^(?:true|false|null|none|disabled|enabled|placeholder|[0-9]+)$/i.test(val.trim());
        if (!detectedSecret && !credentialFreeUrl && !nonSecretLiteral && isSensitiveKeyName(key) && val.length >= 4) {
          detectedSecret = true;
          matchedPatternName = `Sensitive variable '${key}'`;
          confidence = val.length >= 8 ? "likely" : "heuristic";
        }

        if (detectedSecret) {
          const masked = maskSecret(val);
          const locationSource = serverName
            ? `Server '${serverName}' env`
            : "Agent root env";

          findings.push(sanitizeFinding({
            id: `CQ-003-${serverName || "root"}-${key}`,
            ruleId: "CQ-003",
            title: "Exposed Agent Secret",
            description: `Exposed secret detected in ${locationSource}: ${key}=${masked}`,
            severity: confidence === "confirmed" ? "critical" : confidence === "likely" ? "high" : "medium",
            confidence,
            location: {
              file: config.sourcePath,
            },
            evidence: `${key}=${masked} (${matchedPatternName})`,
            impact:
              "Hardcoded credentials can be leaked through agent prompts, logs, or unauthorized repository access.",
            recommendation:
              "Reference credentials via system environment variables rather than hardcoding plaintext secrets.",
            metadata: {
              agentName: config.name,
              serverName,
              key,
              maskedValue: masked,
            },
          }, [val]));
        }
      }
    };

    // Check agent top-level env
    checkEnvBlock(config.envVars);

    // Check each server's env
    for (const server of config.servers) {
      if (server.disabled) continue;
      checkEnvBlock(server.env, server.name);
    }

    const inspectValue = (value: unknown, location: string, seen = new WeakSet<object>()): void => {
      if (typeof value === "string") {
        if (isSecretReference(value)) return;
        const matched = KNOWN_SECRET_PATTERNS.find((pattern) => pattern.regex.test(value));
        if (!matched) return;
        const masked = maskSecret(value);
        findings.push(sanitizeFinding({
          id: `CQ-003-${location}-${matched.name}`.replace(/[^a-zA-Z0-9-]/g, "-"), ruleId: "CQ-003", title: "Exposed Agent Secret",
          description: `Secret detected in configuration field ${location}: ${masked}`, severity: "critical", confidence: "confirmed",
          location: { file: config.sourcePath }, evidence: `${location}: ${masked} (${matched.name})`,
          impact: "Credentials embedded in configuration may be exposed through logs or repository access.",
          recommendation: "Reference credentials through runtime environment variables.", metadata: { agentName: config.name, field: location, maskedValue: masked },
        }, [value]));
        return;
      }
      if (!value || typeof value !== "object" || seen.has(value)) return;
      seen.add(value);
      for (const [key, child] of Object.entries(value)) inspectValue(child, `${location}.${key}`, seen);
    };
    for (const server of config.servers) {
      if (server.disabled) continue;
      inspectValue(server.url, `server.${server.name}.url`);
      inspectValue(server.args, `server.${server.name}.args`);
      inspectValue(server.metadata, `server.${server.name}.metadata`);
    }
    inspectValue(config.metadata, "config.metadata");
    inspectValue(config.tools?.map((tool) => tool.parameters), "tools.parameters");
    return findings;
  },
};
