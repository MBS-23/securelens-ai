import type { Confidence, Severity } from "./types";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
export const CONFIDENCES: Confidence[] = ["CONFIRMED", "HIGH", "MEDIUM", "LOW"];

/** CSS color variable for a severity, shared by badges and charts. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "var(--crit)",
  HIGH: "var(--high)",
  MEDIUM: "var(--med)",
  LOW: "var(--low)",
  INFO: "var(--info)",
};

const SPECIAL_LABELS: Record<string, string> = {
  SAST: "Code (SAST)",
  SECRET: "Secret",
  DEPENDENCY: "Dependency",
  AI_CODE: "AI application code",
  LLM_TEST: "LLM test",
  APPSEC: "Application security",
  AISEC: "AI security",
  AI_SUGGESTED: "AI-suggested",
  NOT_TESTED: "Not tested",
  NOT_VERIFIED: "Not verified",
  NO_KNOWN_VULNERABILITIES: "None known",
  PROVEN_DATAFLOW: "Proven data flow",
  SECURITY_ANALYST: "Security analyst",
  CLI_IMPORT: "CLI import",
};

/** "IN_PROGRESS" → "In progress". */
export function label(value: string | null | undefined): string {
  if (!value) return "—";
  if (SPECIAL_LABELS[value]) return SPECIAL_LABELS[value];
  const text = value.replace(/_/g, " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function relativeTime(value: string | null | undefined, now: Date = new Date()): string {
  if (!value) return "never";
  const date = new Date(value);
  const seconds = Math.round((now.getTime() - date.getTime()) / 1000);
  if (Number.isNaN(seconds)) return "—";
  if (seconds < 45) return "just now";
  const units: [number, string][] = [
    [60, "minute"],
    [3600, "hour"],
    [86400, "day"],
    [604800, "week"],
    [2592000, "month"],
    [31536000, "year"],
  ];
  let unit = "second";
  let amount = seconds;
  for (const [size, name] of units) {
    if (seconds >= size) {
      unit = name;
      amount = Math.floor(seconds / size);
    }
  }
  return `${amount} ${unit}${amount === 1 ? "" : "s"} ago`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDuration(ms: number | undefined | null): string {
  if (ms === undefined || ms === null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

const MONACO_LANGUAGES: Record<string, string> = {
  python: "python",
  javascript: "javascript",
  typescript: "typescript",
  tsx: "typescript",
  php: "php",
  java: "java",
  csharp: "csharp",
  go: "go",
  c: "cpp",
  cpp: "cpp",
  ruby: "ruby",
  kotlin: "kotlin",
  swift: "swift",
  rust: "rust",
  dart: "dart",
  scala: "scala",
};

const EXTENSION_LANGUAGES: Record<string, string> = {
  yml: "yaml",
  yaml: "yaml",
  json: "json",
  md: "markdown",
  sh: "shell",
  sql: "sql",
  html: "html",
  htm: "html",
  xml: "xml",
  ini: "ini",
  toml: "ini",
  dockerfile: "dockerfile",
};

export function monacoLanguage(language: string | null, path: string): string {
  if (language && MONACO_LANGUAGES[language]) return MONACO_LANGUAGES[language];
  const name = path.split("/").pop()?.toLowerCase() ?? "";
  if (name === "dockerfile") return "dockerfile";
  const ext = name.includes(".") ? name.split(".").pop() ?? "" : "";
  return EXTENSION_LANGUAGES[ext] ?? "plaintext";
}

/** Only http(s) links from findings are rendered as links. */
export function safeHref(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}

export function riskColor(index: number | null | undefined): string {
  if (index === null || index === undefined) return "var(--muted)";
  if (index >= 75) return "var(--crit)";
  if (index >= 50) return "var(--high)";
  if (index >= 25) return "var(--med)";
  return "var(--pass)";
}
