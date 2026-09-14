import type { Finding } from "@cerqon/types";
import { isSensitiveKeyName, KNOWN_SECRET_PATTERNS } from "./secrets.js";

export function isSecretReference(value: string): boolean {
  return /^(?:\$\{[A-Za-z_][\w]*\}|\$[A-Za-z_][\w]*|<[^<>]+>)$/.test(value.trim());
}

/** Never calls toJSON or mutates the source. Cycles cannot escape to a reporter. */
export function sanitizeUnknownValue(value: unknown, secrets: readonly string[] = []): unknown {
  const seen = new WeakSet<object>();
  const redact = (text: string): string => {
    let result = text;
    for (const secret of [...secrets].filter(Boolean).sort((a, b) => b.length - a.length)) {
      result = result.split(secret).join("****");
    }
    result = result.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/]*@/gi, "$1****:****@");
    result = result.replace(/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)/g, "****");
    for (const { regex } of KNOWN_SECRET_PATTERNS) {
      result = result.replace(new RegExp(regex.source, "gi"), "****");
    }
    result = result.replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]+)\b/g, "****");
    result = result.replace(/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)/g, "****");
    result = result.replace(/((?:--)?[\w-]*(?:password|secret|token|api[_-]?key|access[_-]?key)[\w-]*[=:]\s*|--[\w-]*(?:password|secret|token|api[_-]?key|access[_-]?key)[\w-]*\s+)("[^"]*"|'[^']*'|[^\s&,;]+)/gi,
      (_match, prefix: string, value: string) => prefix + (value.includes("****") ? value : "****"));
    // Prevent terminal control characters in configuration-controlled strings.
    return Array.from(result).filter((char) => char === "\n" || char === "\t" || (char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127)).join("");
  };
  const visit = (item: unknown): unknown => {
    if (typeof item === "string") return redact(item);
    if (item === null || typeof item !== "object") return item;
    if (seen.has(item)) return "[Circular]";
    seen.add(item);
    const result = Array.isArray(item)
      ? item.map((child, index) => typeof child === "string" && index > 0 &&
          typeof item[index - 1] === "string" && /^--?[\w-]+$/.test(item[index - 1]) &&
          isSensitiveKeyName(item[index - 1].replace(/-/g, "_")) ? "****" : visit(child))
      : Object.fromEntries(Object.entries(item).map(([key, child]) => [
          redact(key),
          typeof child === "string" && isSensitiveKeyName(key) && child && !isSecretReference(child)
            ? "****" : visit(child),
        ]));
    seen.delete(item);
    return result;
  };
  return visit(value);
}

/** Context lets a secret discovered in env also be removed from a different field. */
export function collectSecretValues(value: unknown): string[] {
  const secrets = new Set<string>();
  const seen = new WeakSet<object>();
  const visit = (item: unknown): void => {
    if (!item || typeof item !== "object" || seen.has(item)) return;
    seen.add(item);
    for (const [key, child] of Object.entries(item)) {
      if (typeof child === "string" && isSensitiveKeyName(key) && child.length >= 4 && !isSecretReference(child)) secrets.add(child);
      visit(child);
    }
  };
  visit(value);
  return [...secrets];
}

export function sanitizeFinding(finding: Finding, secrets: readonly string[] = []): Finding {
  return sanitizeUnknownValue(finding, secrets) as Finding;
}
