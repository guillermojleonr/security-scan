Fixtures for manual runs and automated tests.

Manual scan (from repo root):
  python security-scan.py fixtures/npm-locked-ok
  python security-scan.py fixtures/npm-ranges-bad
  python security-scan.py fixtures/npm-lock-bad-version
  python security-scan.py fixtures/npm-lock-v1-bad
  python security-scan.py fixtures/python-requirements

Automated npm policy checks:
  python -m unittest tests.test_fixtures -v

Note: Full scans require optional tools (gitleaks, semgrep, pip-audit, npm, trivy) on PATH.
The unittest module only checks collect_npm_lock_violations() against these folders.
