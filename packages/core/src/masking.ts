/**
 * Masks a secret string so that sensitive tokens are never exposed in logs, findings, or reports.
 *
 * Example:
 * Input:  "sk-ant-api03-1234567890abcdef"
 * Output: "sk-ant-****...****"
 */
export function maskSecret(secret: string): string {
  if (!secret) return "";
  const trimmed = secret.trim();
  if (trimmed.length <= 4) {
    return "****";
  }

  // If starts with known prefixes like sk-ant-, sk-, ghp_, AKIA
  const prefixes = ["sk-ant-", "sk-proj-", "sk-", "ghp_", "gho_", "AKIA", "xoxb-", "xoxp-"];
  for (const prefix of prefixes) {
    if (trimmed.startsWith(prefix)) {
      return `${prefix}****...****`;
    }
  }

  // Default prefix of at most 4 chars
  const prefixLength = Math.min(3, Math.floor(trimmed.length / 4));
  const prefix = trimmed.slice(0, prefixLength);
  return `${prefix}****...****`;
}
