import fs from "node:fs/promises";
import path from "node:path";
import type { AgentAdapter, AgentConfiguration, AgentTool, ScanDiagnostic } from "@cerqon/types";
import { parseMCPServers } from "./parser-utils.js";

export function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException)?.code === "ENOENT";
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid object");
  return value as Record<string, unknown>;
}
export function stringMap(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  const result = object(value);
  if (Object.values(result).some((v) => typeof v !== "string")) throw new Error("Invalid string map");
  return result as Record<string, string>;
}

export async function readConfiguration(file: string, adapter: string, diagnostics: ScanDiagnostic[], allowMissing = false): Promise<AgentConfiguration | null> {
  let raw: string;
  try { raw = await fs.readFile(file, "utf8"); }
  catch (error) {
    if (allowMissing && isMissing(error)) return null;
    diagnostics.push({ code: "CERQON_CONFIGURATION_READ_ERROR", severity: "error", message: "Configuration could not be read.", file, adapter });
    return null;
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw.replace(/^\uFEFF/, "")); }
  catch {
    // Never expose JSON.parse's message: it may contain raw configuration secrets.
    diagnostics.push({ code: "CERQON_INVALID_JSON", severity: "error", message: "Configuration contains malformed JSON.", file, adapter });
    return null;
  }
  try {
    const cfg = object(parsed);
    const rawServers = cfg.mcpServers ?? cfg.servers ?? (cfg.command ? { default: cfg } : undefined);
    if (rawServers === undefined && !Array.isArray(cfg.tools)) throw new Error("Unsupported configuration");
    if (cfg.name !== undefined && typeof cfg.name !== "string") throw new Error("Invalid name");
    let tools: AgentTool[] | undefined;
    if (cfg.tools !== undefined) {
      if (!Array.isArray(cfg.tools)) throw new Error("Invalid tools");
      tools = cfg.tools.map((rawTool) => {
        const tool = object(rawTool);
        if (typeof tool.name !== "string" || (tool.description !== undefined && typeof tool.description !== "string")) throw new Error("Invalid tool");
        return { name: tool.name, description: tool.description as string | undefined };
      });
    }
    return { id: `${adapter}:${file}`, name: typeof cfg.name === "string" ? cfg.name : adapter,
      adapterName: adapter, sourcePath: file, servers: rawServers === undefined ? [] : parseMCPServers(rawServers),
      tools, envVars: stringMap(cfg.env), metadata: cfg.metadata === undefined ? undefined : object(cfg.metadata) };
  } catch {
    diagnostics.push({ code: "CERQON_INVALID_CONFIGURATION", severity: "error", message: "Unsupported configuration structure or invalid field type.", file, adapter });
    return null;
  }
}

export class FileAdapter implements AgentAdapter {
  constructor(readonly name: string, private readonly candidates: string[]) {}
  async detect(targetDir: string): Promise<boolean> {
    for (const candidate of this.candidates) {
      try { await fs.access(path.join(targetDir, candidate)); return true; }
      catch (error) { if (!isMissing(error)) throw error; }
    }
    return false;
  }
  async discover(targetDir: string, diagnostics: ScanDiagnostic[] = []): Promise<AgentConfiguration[]> {
    const configs: AgentConfiguration[] = [];
    for (const candidate of this.candidates) {
      const cfg = await readConfiguration(path.join(targetDir, candidate), this.name, diagnostics, true);
      if (cfg) configs.push(cfg);
    }
    return configs;
  }
}
