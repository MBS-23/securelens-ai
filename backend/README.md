# SecureLens AI — backend

The Python package behind SecureLens AI: the Application Security Engine
(SAST for eight languages, secrets, dependencies), reporting, the `securelens`
CLI, and the API server and worker.

```bash
pip install -e ".[server,dev]"
securelens scan path/to/code          # table output, exit code 1 if the security gate fails
securelens findings --show SL-001     # "Why did SecureLens detect this?"
securelens report --format html -o report.html
```

See the project README one level up for the full documentation.
