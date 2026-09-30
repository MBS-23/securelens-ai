"""CI templates written by ``securelens init --ci``."""

from __future__ import annotations

PACKAGE_SPEC = "securelens-ai @ git+https://github.com/MBS-23/securelens-ai.git#subdirectory=backend"

GITHUB_WORKFLOW = f"""\
# SecureLens AI — static application security testing on every push and pull request.
name: SecureLens AI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # upload SARIF to GitHub code scanning

jobs:
  securelens:
    runs-on: ubuntu-latest
    env:
      SECURELENS_PACKAGE: "{PACKAGE_SPEC}"
      # Optional: a stable key so secret fingerprints match between runs.
      SECURELENS_SECRET_HASH_KEY: ${{{{ secrets.SECURELENS_SECRET_HASH_KEY }}}}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install SecureLens AI
        run: pip install "$SECURELENS_PACKAGE"
      - name: Scan
        # Exit code 1 means the security gate in .securelens.yml failed.
        run: >-
          securelens scan .
          --sarif-out securelens.sarif
          --html-out securelens-report.html
          --markdown-out securelens-summary.md
          --json-out securelens.json
      - name: Job summary
        if: always()
        run: cat securelens-summary.md >> "$GITHUB_STEP_SUMMARY" || true
      - name: Upload SARIF to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: securelens.sarif
          category: securelens
      - name: Keep the HTML and JSON reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: securelens-report
          path: |
            securelens-report.html
            securelens.json
"""

GITLAB_CI = f"""\
# SecureLens AI — include this file from .gitlab-ci.yml:
#
#   include:
#     - local: securelens.gitlab-ci.yml
#
securelens:
  stage: test
  image: python:3.12-slim
  variables:
    SECURELENS_PACKAGE: "{PACKAGE_SPEC}"
  before_script:
    - apt-get update -qq && apt-get install -y -qq --no-install-recommends git > /dev/null
    - pip install --quiet "$SECURELENS_PACKAGE"
  script:
    # Exit code 1 means the security gate in .securelens.yml failed.
    - securelens scan . --json-out securelens.json --sarif-out securelens.sarif --html-out securelens-report.html
  artifacts:
    when: always
    expose_as: "SecureLens report"
    paths:
      - securelens-report.html
      - securelens.json
      - securelens.sarif
"""
