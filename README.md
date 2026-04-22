# security-scan

This repository provides a small wrapper script (`security-scan.py`) that runs a set of popular security tools against your project.

**Requirements**
- Python 3
- The command-line tools you want to use installed and available on `PATH`: `gitleaks`, `semgrep`, `pip-audit`, `npm`, `trivy`.

On Windows, ensure the corresponding executables are available (for example via Scoop, Chocolatey, or official installers). The script checks for tools before running them and will skip any that are not found.



**Usage**
To use it simply, create a security-scan.bat inside C:\users\{user}\bin (which is in PATH)

Now you can run
`security-scan .` or `security-scan path/to/repo`

The script will print which checks it runs and will skip tools that are not installed.

**Customizing**
- Edit `security-scan.py` to change command flags, add other tools, or change the order of checks.

**Notes**
- The script uses shell commands and `subprocess.run(..., shell=True)`; if you integrate this into CI, consider adjusting invocation or shell settings for your environment.
- The wrapper is intentionally simple — it aims to centralize common local scans, not replace full CI/CD security pipelines.

**Files**
- `security-scan.py`: main wrapper script.

**Tool descriptions**

- `gitleaks`: Fast secrets scanner for Git repositories — detects hardcoded secrets (API keys, tokens, credentials) in commits, branches, and working trees using regex and entropy rules. Useful locally and in CI to prevent secret leaks.

- `semgrep`: Lightweight static analysis and pattern-matching engine — finds security issues, code quality problems, and custom patterns across many languages using expressive rules. Good for quick SAST and custom policy enforcement.

- `pip-audit`: Python dependency auditor — inspects installed packages or a `requirements.txt` file and reports known vulnerabilities in Python dependencies, referencing vulnerability databases and recommending upgrades.

- `npm audit`: Node.js package auditor — analyzes `package.json`/`package-lock.json` to find known vulnerabilities in npm packages, shows severity, and provides suggested fixes (e.g., `npm audit fix`).

- `trivy`: Comprehensive scanner for container images and filesystems — detects OS/package vulnerabilities, insecure configurations, and secrets; can run local filesystem scans (`trivy fs .`) and image scans.