import npa from "npm-package-arg";

export interface PackageSpecAnalysis {
  name?: string;
  rawSpec: string;
  type: string;
  isScoped: boolean;
  isExactVersion: boolean;
  isMutable: boolean;
  reason: string;
}

export function analyzePackageSpec(spec: string): PackageSpecAnalysis {
  try {
    const parsed = npa(spec);
    const target = parsed.type === "alias" ? (parsed as npa.AliasResult).subSpec : parsed;
    const isExactVersion = target.type === "version";
    const pinnedGit = target.type === "git" && /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i.test(target.gitCommittish ?? "");
    const local = target.type === "directory" || target.type === "file";
    const isMutable = !isExactVersion && !pinnedGit && !local;
    return { name: parsed.name ?? undefined, rawSpec: parsed.rawSpec, type: parsed.type, isScoped: !!parsed.scope,
      isExactVersion, isMutable, reason: isExactVersion ? "Exact registry version; origin and package contents are not verified."
        : pinnedGit ? "Git source pinned to a full commit hash; origin is not verified."
        : local ? "Local source; package pinning does not apply."
        : "Source is not pinned to an exact registry version or full Git commit." };
  } catch {
    return { rawSpec: spec, type: "invalid", isScoped: spec.startsWith("@"), isExactVersion: false, isMutable: true, reason: "Package specification could not be verified." };
  }
}

/** Parse runner options before the executable. Application arguments are not dependencies. */
export function executionPackageSpecs(command?: string, args: string[] = []): string[] {
  const binary = command?.replace(/\\/g, "/").split("/").pop()?.toLowerCase().replace(/\.(cmd|exe)$/, "");
  let tokens = [...args];
  if (binary === "npm" && tokens[0] === "exec") tokens = tokens.slice(1);
  else if (binary === "pnpm" && tokens[0] === "dlx") tokens = tokens.slice(1);
  else if (binary !== "npx" && binary !== "bunx") {
    return command && /^(git\+|https?:\/\/|github:)/i.test(command) ? [command] : [];
  }
  const specs: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === "--package" || token === "-p") { specs.push(tokens[++i] ?? ""); continue; }
    if (token.startsWith("--package=")) { specs.push(token.slice(10)); continue; }
    if (token.startsWith("-p") && token.length > 2 && !token.startsWith("--")) { specs.push(token.slice(2)); continue; }
    if (["--registry", "--cache", "--userconfig", "--prefix"].includes(token)) { i++; continue; }
    if (["-c", "--call"].includes(token)) break;
    if (token === "--") { if (!specs.length && tokens[i + 1]) specs.push(tokens[i + 1]); break; }
    if (token.startsWith("-")) continue;
    if (!specs.length) specs.push(token);
    break;
  }
  return specs;
}
