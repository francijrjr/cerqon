export interface SecretPattern {
  name: string;
  regex: RegExp;
  description: string;
}

export const KNOWN_SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "OpenAI API Key",
    regex: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/,
    description: "OpenAI API Key detected in configuration",
  },
  {
    name: "Anthropic API Key",
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/,
    description: "Anthropic Claude API Key detected in configuration",
  },
  {
    name: "AWS Access Key ID",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    description: "AWS Access Key ID detected in configuration",
  },
  {
    name: "GitHub Token",
    regex: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/,
    description: "GitHub personal access token detected in configuration",
  },
  {
    name: "Slack Token",
    regex: /\bxox[baprs]-[0-9a-zA-Z]{10,}\b/,
    description: "Slack API token detected in configuration",
  },
  {
    name: "Private Key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    description: "Cryptographic private key detected in configuration",
  },
  {
    name: "Database Connection String",
    regex: /(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+/,
    description: "Database connection string containing embedded credentials",
  },
];

export const SENSITIVE_KEY_NAMES = [
  "API_KEY",
  "SECRET_KEY",
  "ACCESS_KEY",
  "SECRET",
  "TOKEN",
  "PASSWORD",
  "AUTH_TOKEN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "GITHUB_TOKEN",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "DATABASE_URL",
  "PRIVATE_KEY",
];

export function isSensitiveKeyName(key: string): boolean {
  const upper = key.toUpperCase();
  return SENSITIVE_KEY_NAMES.some((k) => upper.includes(k));
}
