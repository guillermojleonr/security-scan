# security-scan

Nowadays we are seeing many new sofisticated attacks malware, and when we clone repositories from the internet I can't stop thinking that I don't know what I'm downloading.

Recently (2026), Axios, a popular library was infected with malware, and the only thing you had to do to get infected were to run an npm install: if you had a package.json with a not safe-specific axios version, you were cooked.

That's the reason I decided to create a small wrapper script (`security-scan.py`) that runs a set of popular security tools against your project. 

Before you execute anything or run npm install, run this against the repository to try to find security issues

## Requirements
- Python 3
- The command-line tools you want to use installed and available on `PATH`: `gitleaks`, `semgrep`, `pip-audit`, `npm`, `trivy`.

On Windows, ensure the corresponding executables are available (for example via Scoop, Chocolatey, or official installers). The script checks for tools before running them and will skip any that are not found.

## Usage
Create a security-scan.bat inside C:\users\{user}\bin (which is in PATH) and run `security-scan .` or `security-scan path/to/repo`, otherwise ``path/to/security-scan.py path/to/repo``

The script will print which checks it runs and will skip tools that are not installed.

**Customizing**
- Edit `security-scan.py` to change command flags, add other tools, or change the order of checks.

**Notes**
- Uses shell commands and `subprocess.run(..., shell=True)`; if you integrate this into CI, consider adjusting invocation or shell settings for your environment.
- The wrapper is intentionally simple — it aims to centralize common local scans, not replace full CI/CD security pipelines.


## Features

- **npm Lock Policy Validation**: Checks `package.json` and `package-lock.json` for unpinned versions that could lead to supply-chain attacks. Flags:
  - Version ranges (`^1.2.3`, `~1.2.3`)
  - Dist-tags (`latest`, `next`, `canary`, etc.)
  - Wildcards (`*`, `1.x`, `1.2.x`)
  - Comparison operators (`>=`, `<=`, `>`, `<`)
  - Validates all dependency types (dependencies, devDependencies, optionalDependencies, peerDependencies, overrides)
  - Supports both lockfile v1 and v2+ formats
  - Helps ensure reproducible builds with exact versions

**Tool descriptions**

- `gitleaks`: Fast secrets scanner for Git repositories — **detects hardcoded secrets** (API keys, tokens, credentials) in commits, branches, and working trees using regex and entropy rules. Useful locally and in CI to prevent secret leaks.

- `semgrep`: Lightweight **static analysis and pattern-matching engine** — finds security issues, code quality problems, and custom patterns across many languages using expressive rules. Good for quick SAST and custom policy enforcement. Includes custom rules for detecting invisible Unicode characters.

- `pip-audit`: Python dependency auditor — inspects installed packages or a `requirements.txt` file and **reports known vulnerabilities in Python dependencies**, referencing vulnerability databases and recommending upgrades.

- `npm audit`: Node.js package auditor — analyzes `package.json`/`package-lock.json` to **find known vulnerabilities in npm packages**, shows severity, and provides suggested fixes (e.g., `npm audit fix`).

- `trivy`: Comprehensive scanner for container images and filesystems — detects OS/package vulnerabilities, insecure configurations, and secrets; can run local filesystem scans (`trivy fs .`) and image scans.

## Contributions
Feel free to contribute, also if you know about another project with the same purpose ¡let me know!, maybe some people already solved this concern.