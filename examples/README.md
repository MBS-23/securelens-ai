# Examples

**These applications are intentionally vulnerable.** They exist to demonstrate
SecureLens AI. Never deploy or run them as services.

| Folder | What it shows |
|---|---|
| `vulnerable-shop/` | A small multi-language "shop" (Python, JavaScript/TypeScript, PHP, Java, C#, Go, C, C++) with injection, XSS, SSRF, path traversal, deserialization, weak crypto, memory-safety and LLM-output issues. |
| `retest-demo/before/` → `after/` | The Vulnerable → Fix → Retest loop. `after/` fixes most issues, leaves one in place and introduces a new one. |

Credential examples are not committed: test suites generate them at runtime,
so no credential-shaped string lives in this repository.

## Try it

```bash
cd backend
pip install -e ".[server,dev]"

# Scan: table output, exit code 1 because the security gate fails
securelens scan ../examples/vulnerable-shop --vuln-source none --html-out report.html

# Why did SecureLens report SL-003?
securelens findings --show SL-003

# Vulnerable → Fix → Retest
securelens scan ../examples/retest-demo/before --vuln-source none --json-out before.json
securelens retest ../examples/retest-demo/after --baseline before.json --vuln-source none
```

`--vuln-source none` skips the online advisory lookup (api.osv.dev); the
report then marks dependencies **NOT VERIFIED** instead of claiming they are safe.

Findings are matched by their path inside the scanned folder, so `before/`
and `after/` compare correctly even though they are different directories.
