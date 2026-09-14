import type { AgentConfiguration, Finding, Rule, RuleContext, ScanDiagnostic } from "@cerqon/types";

export class RulesEngine {
  constructor(private readonly rules: Rule[]) {}
  evaluate(config: AgentConfiguration, allConfigs: AgentConfiguration[] = [], diagnostics: ScanDiagnostic[] = []): Finding[] {
    const context: RuleContext = { config, allConfigs, diagnostics };
    return this.rules.flatMap((rule) => {
      if (!rule.isImplemented) return [];
      try { return rule.evaluate(context); }
      catch { diagnostics.push({ code: "CERQON_RULE_EVALUATION_ERROR", severity: "error", message: `Rule ${rule.id} could not be evaluated.`, file: config.sourcePath, adapter: config.adapterName }); return []; }
    });
  }
}
