import type { AgentConfiguration, Finding, Rule, ScanDiagnostic } from "@cerqon/types";
import { ACTIVE_CERQON_RULES, ALL_CERQON_RULES } from "./rules/index.js";
import { calculateRiskScore, type ScoreCalculationResult } from "./score.js";
import { collectSecretValues, sanitizeFinding } from "@cerqon/core";
import { deduplicateFindings } from "./deduplication.js";

export class RiskEngine {
  private rules: Rule[];

  constructor(customRules?: Rule[]) {
    this.rules = customRules || ACTIVE_CERQON_RULES;
  }

  getAllRules(): Rule[] {
    return ALL_CERQON_RULES;
  }

  getActiveRules(): Rule[] {
    return this.rules;
  }

  evaluateConfig(
    config: AgentConfiguration,
    allConfigs?: AgentConfiguration[],
    diagnostics: ScanDiagnostic[] = []
  ): Finding[] {
    const findings: Finding[] = [];
    const active = (cfg: AgentConfiguration): AgentConfiguration => ({ ...cfg, servers: cfg.servers.filter((server) => !server.disabled) });
    const context = { config: active(config), allConfigs: allConfigs?.map(active) };

    for (const rule of this.rules) {
      if (!rule.isImplemented) continue;
      try {
        const ruleFindings = rule.evaluate(context);
        findings.push(...ruleFindings);
      } catch {
        diagnostics.push({ code: "CERQON_RULE_EVALUATION_ERROR", severity: "error", message: `Rule ${rule.id} could not be evaluated.`, file: config.sourcePath, adapter: config.adapterName });
      }
    }

    const secrets = collectSecretValues(config);
    return findings.map((finding) => sanitizeFinding(finding, secrets));
  }

  evaluateAll(configs: AgentConfiguration[], diagnostics: ScanDiagnostic[] = []): {
    findings: Finding[];
    scoreResult: ScoreCalculationResult;
  } {
    const allFindings: Finding[] = [];

    for (const config of configs) {
      const findings = this.evaluateConfig(config, configs, diagnostics);
      allFindings.push(...findings);
    }

    const findings = deduplicateFindings(allFindings);
    const scoreResult = calculateRiskScore(findings);

    return {
      findings,
      scoreResult,
    };
  }
}
