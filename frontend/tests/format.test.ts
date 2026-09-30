import { describe, expect, it } from "vitest";
import { formatBytes, label, monacoLanguage, relativeTime, safeHref } from "../src/lib/format";

describe("safeHref", () => {
  it("allows only http and https links", () => {
    expect(safeHref("https://cwe.mitre.org/data/definitions/89.html")).toBe("https://cwe.mitre.org/data/definitions/89.html");
    expect(safeHref("http://example.test/a")).toBe("http://example.test/a");
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("JaVaScRiPt:alert(1)")).toBeNull();
    expect(safeHref("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(safeHref("//evil.test/x")).toBeNull();
    expect(safeHref("not a url")).toBeNull();
  });
});

describe("label", () => {
  it("humanises enum values", () => {
    expect(label("IN_PROGRESS")).toBe("In progress");
    expect(label("FALSE_POSITIVE")).toBe("False positive");
    expect(label(null)).toBe("—");
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-09-30T12:00:00Z");
  it("describes elapsed time", () => {
    expect(relativeTime("2026-09-30T11:59:50Z", now)).toBe("just now");
    expect(relativeTime("2026-09-30T11:00:00Z", now)).toBe("1 hour ago");
    expect(relativeTime("2026-09-27T12:00:00Z", now)).toBe("3 days ago");
    expect(relativeTime(null, now)).toBe("never");
  });
});

describe("formatting helpers", () => {
  it("formats sizes and editor languages", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(monacoLanguage("tsx", "src/App.tsx")).toBe("typescript");
    expect(monacoLanguage(null, "deploy/Dockerfile")).toBe("dockerfile");
    expect(monacoLanguage(null, "notes.unknown")).toBe("plaintext");
  });
});
