import type { AgentConfiguration, Finding, Rule } from "@cerqon/types";
import { ACTIVE_CERQON_RULES, ALL_CERQON_RULES } from "./rules/index.js";
import { calculateRiskScore, type ScoreCalculationResult } from "./score.js";

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
    allConfigs?: AgentConfiguration[]
  ): Finding[] {
    const findings: Finding[] = [];
    const context = { config, allConfigs };

    for (const rule of this.rules) {
      if (!rule.isImplemented) continue;
      try {
        const ruleFindings = rule.evaluate(context);
        findings.push(...ruleFindings);
      } catch (err) {
        // Safe evaluation guard
        console.error(`Error evaluating rule ${rule.id} on ${config.name}:`, err);
      }
    }

    return findings;
  }

  evaluateAll(configs: AgentConfiguration[]): {
    findings: Finding[];
    scoreResult: ScoreCalculationResult;
  } {
    const allFindings: Finding[] = [];

    for (const config of configs) {
      const findings = this.evaluateConfig(config, configs);
      allFindings.push(...findings);
    }

    const scoreResult = calculateRiskScore(allFindings);

    return {
      findings: allFindings,
      scoreResult,
    };
  }
}
