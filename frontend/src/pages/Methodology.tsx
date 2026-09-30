import { Card, PageHeader, Pill } from "../components/ui";

const VERIFICATION = [
  ["DETECTED", "A deterministic scanner reported it with recorded evidence (data flow, pattern, secret format, advisory)."],
  ["AI_SUGGESTED", "Only an AI signal supports it. Shown for review, never counted as confirmed, and excluded from the gate by default."],
  ["CONFIRMED", "A person confirmed it, or a dynamic test produced direct evidence."],
  ["FALSE_POSITIVE", "Triaged as not a real issue, with a recorded reason."],
  ["NOT_TESTED", "SecureLens could not test it (for example, the scanner did not run)."],
];

const RETEST = [
  ["RESOLVED", "The file was analysed again by the same scanner and the issue is gone."],
  ["STILL_OPEN", "Found again — at the same code, or in the same function after an edit (fuzzy match)."],
  ["NEW", "Present now, not in the baseline scan."],
  ["REGRESSION", "Resolved earlier and back again. Fails the gate by default."],
  ["NOT_REPRODUCED", "The file is gone, so its absence does not prove a fix."],
  ["NOT_TESTED", "The file or its scanner was not part of the new scan."],
];

export default function Methodology() {
  return (
    <>
      <PageHeader title="How SecureLens decides" subtitle="Every number and label in SecureLens can be traced back to these rules." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Severity, confidence, exploitability">
          <div className="space-y-3 text-sm text-ink-2">
            <p>
              <b className="text-ink">Severity</b> is how bad the issue is if it is real. <b className="text-ink">Confidence</b> is how strongly the
              evidence supports it. <b className="text-ink">Exploitability</b> says what kind of evidence exists: a proven data flow from untrusted
              input to a dangerous operation, a likely one, a possible one whose input origin could not be traced, or a pattern match only.
            </p>
            <p>These axes are independent: a critical-severity issue can have medium confidence, and SecureLens shows both.</p>
          </div>
        </Card>
        <Card title="Verification">
          <ul className="space-y-2 text-sm">
            {VERIFICATION.map(([k, v]) => (
              <li key={k} className="flex gap-3">
                <Pill>{k}</Pill>
                <span className="text-ink-2">{v}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="SecureLens Risk Index (SRI)">
          <div className="space-y-3 text-sm text-ink-2">
            <p className="font-mono text-ink">SRI = 100 × (1 − e^(−Σ risk / K))</p>
            <p>
              Each open finding contributes severity × confidence × exploitability × exposure × business criticality (only when set) × verification
              × status. Resolved, false-positive and accepted-risk findings contribute 0. Weights and K are configurable per organization.
            </p>
            <p>It is a SecureLens-specific prioritisation aid — not CVSS, and not a measure of overall security.</p>
          </div>
        </Card>
        <Card title="Retest results">
          <ul className="space-y-2 text-sm">
            {RETEST.map(([k, v]) => (
              <li key={k} className="flex gap-3">
                <Pill>{k}</Pill>
                <span className="text-ink-2">{v}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-muted">A suggested fix never resolves a finding. Only a new scan or an explicit, audited human decision does.</p>
        </Card>
        <Card title="What SecureLens does not claim" className="lg:col-span-2">
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-ink-2">
            <li>Static analysis can miss vulnerabilities and can report code that is not exploitable in practice. Review findings before acting.</li>
            <li>Business logic, authorization design, runtime configuration and infrastructure are not assessed by the code scanners.</li>
            <li>Dependencies without an exact version, or scanned without an advisory source, are NOT VERIFIED — never assumed safe.</li>
            <li>No report represents complete security assurance.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}
