"""SecureLens AI — AI-Powered Application & LLM Security Testing Platform.

The package is split so that the scanning engines, the AI security engine,
reporting and the CLI run without a database or web server:

* ``securelens.scanners``   — Application Security Engine (SAST, secrets, dependencies)
* ``securelens.evaluation`` — AI/LLM Security Engine (prompt, data, RAG, agent tests)
* ``securelens.findings``   — unified finding model, correlation, risk and gate
* ``securelens.ai``         — provider abstraction, analysis and remediation
* ``securelens.reporting``  — JSON, SARIF, HTML and Markdown output
* ``securelens.cli``        — the ``securelens`` command

The server side (``api``, ``core``, ``models``, ``services``, ``worker``)
needs the ``server`` extra.
"""

from securelens.version import __version__

__all__ = ["__version__"]
