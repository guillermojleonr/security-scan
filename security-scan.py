"""Security-scan

Usage: python security_scan.py /path/to/repo
This script runs a set of popular security tools against the specified repository (or current directory if no path is given). It includes:
- Secrets scanning with gitleaks
- Static analysis with semgrep
- Python dependency audit with pip-audit (if requirements.txt exists)
- Node dependency audit with npm audit (if package.json exists)
- Local filesystem vulnerability scan with trivy
"""

import subprocess
import shutil
import os
import re
import sys
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Force UTF-8 for stdout and child processes on Windows to avoid
# UnicodeEncodeError when tools emit invisible Unicode characters.
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Ensure child Python processes use UTF-8 for stdout/stderr
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
# Enable Python UTF-8 mode for child processes (fix default open() encoding on Windows)
os.environ.setdefault("PYTHONUTF8", "1")

# Store security issues found during scan
SECURITY_ISSUES = []

def add_security_issue(tool, issue_type, details):
    """Add a security issue to the list for email notification"""
    SECURITY_ISSUES.append({
        "tool": tool,
        "type": issue_type,
        "details": details
    })

def send_email_notification(repo_path):
    """Send email notification if security issues were found"""
    if not EMAIL_CONFIG["enabled"] or not SECURITY_ISSUES:
        return
    
    try:
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG["from_email"]
        msg['To'] = EMAIL_CONFIG["to_email"]
        msg['Subject'] = f'{EMAIL_CONFIG["subject_prefix"]} Issues found in {os.path.basename(repo_path)}'
        
        # Build email body
        body = f"Security scan completed for: {repo_path}\n\n"
        body += f"⚠️ {len(SECURITY_ISSUES)} security issue(s) found:\n\n"
        
        for i, issue in enumerate(SECURITY_ISSUES, 1):
            body += f"{i}. {issue['tool']} - {issue['type']}\n"
            body += f"   {issue['details']}\n\n"
        
        body += "Please review and address these issues.\n"
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        with smtplib.SMTP_SSL(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.login(EMAIL_CONFIG["smtp_username"], EMAIL_CONFIG["smtp_password"])
            server.send_message(msg)
        
        print(f"📧 Email notification sent to {EMAIL_CONFIG['to_email']}")
    except Exception as e:
        print(f"⚠️ Failed to send email notification: {e}")

# Configuration: Enable/disable security tools
CONFIG = {
    "npm_lock_policy": True,       # Check npm lock policy (exact versions only)
    "gitleaks": True,              # Scan for secrets with gitleaks
    "semgrep": False,               # Static analysis with semgrep
    "pip_audit": True,             # Python dependency audit with pip-audit
    "npm_audit": True,             # Node dependency audit with npm audit
    "trivy": True,                 # Filesystem vulnerability scan with trivy
}

# Email configuration
EMAIL_CONFIG = {
    "enabled": True,               # Enable email notifications
    "smtp_server": os.getenv("SMTP_SERVER"),  # SMTP server
    "smtp_port": int(os.getenv("SMTP_PORT")),              # SMTP port
    "smtp_username": os.getenv("SMTP_USERNAME"),  # SMTP username
    "smtp_password": os.getenv("SMTP_PASSWORD"),     # SMTP password (use app password for Gmail)
    "from_email": os.getenv("FROM_EMAIL"),     # From email
    "to_email": os.getenv("TO_EMAIL"),      # To email
    "subject_prefix": "[Security Scan Alert]",  # Email subject prefix
}


def run_command(cmd, title, capture_output=True):
    print(f"\n🔍 {title}...")
    try:
        if capture_output:
            result = subprocess.run(
                cmd,
                shell=True,
                check=False,
                env=os.environ,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            if result.stdout.strip():
                print(result.stdout)
            if result.stderr.strip():
                print(result.stderr)
            if result.returncode != 0:
                print(f"⚠️ Command exited with code {result.returncode}")
            return result
        else:
            result = subprocess.run(cmd, shell=True, check=False, env=os.environ)
            return result
    except Exception as e:
        print(f"⚠️ Error running {cmd}: {e}")
        return None


def print_semgrep_summary(path="semgrep-results.json", max_items=20):
    if not os.path.exists(path):
        print(f"ℹ️ Semgrep: results file not found: {path}")
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"⚠️ Failed to read Semgrep results: {e}")
        return
    results = data.get("results", [])
    if not results:
        print("✅ Semgrep: no findings")
        return
    print(f"⚠️ Semgrep: {len(results)} finding(s). Showing up to {max_items}:")
    for r in results[:max_items]:
        file_path = r.get("path", "<unknown>")
        start = r.get("start", {})
        line = start.get("line", "?")
        col = start.get("col", "?")
        message = r.get("extra", {}).get("message", "")
        check_id = r.get("check_id") or r.get("rule_id") or r.get("check_name") or ""
        print(f"- {file_path}:{line}:{col} {check_id} - {message}")


def command_exists(cmd):
    return (
    shutil.which(cmd) is not None
    )


# Whole-string npm dist-tags (not valid exact semver by themselves)
_NPM_DIST_TAGS = frozenset({
    "latest",
    "next",
    "canary",
    "dev",
    "stable",
    "nightly",
    "preview",
    "beta",
    "alpha",
    "rc",
    "experimental",
    "experiment",
})


def _npm_version_violates_lock_policy(version):
    """True if version is not pinned to an exact semver (ranges, tags, wildcards)."""
    if not isinstance(version, str):
        return False
    v = version.strip()
    if not v:
        return True

    if v.lower() in _NPM_DIST_TAGS:
        return True

    if v.startswith("npm:"):
        rest = v[4:]
        if "@" in rest:
            _, ver_part = rest.rsplit("@", 1)
            if not ver_part:
                return True
            return _npm_version_violates_lock_policy(ver_part)
        return False

    if v.startswith("workspace:"):
        rest = v[len("workspace:") :].strip()
        if not rest:
            return True
        return _npm_version_violates_lock_policy(rest)

    if v.startswith(("git+", "http://", "https://", "file:", "link:")):
        return False

    if v.startswith("="):
        return _npm_version_violates_lock_policy(v[1:].strip())

    if v.startswith(("^", "~")):
        return True

    if v.startswith((">=", "<=", "!=")):
        return True
    if v.startswith(">"):
        return True
    if v.startswith("<"):
        return True

    if "||" in v:
        return True
    if " - " in v:
        return True

    if "*" in v:
        return True

    if re.match(r"(?i)^[x*](\.[x*])*$", v):
        return True
    if re.match(r"(?i)^\d+\.[x*](\.\d+)?$", v):
        return True
    if re.match(r"(?i)^\d+\.\d+\.[x*]$", v):
        return True

    return False


def _check_overrides_values(overrides, violations, prefix="overrides"):
    if not isinstance(overrides, dict):
        return
    for key, val in overrides.items():
        path = f"{prefix}.{key}"
        if isinstance(val, str):
            if _npm_version_violates_lock_policy(val):
                violations.append((path, val))
        elif isinstance(val, dict):
            _check_overrides_values(val, violations, path)


def _walk_lockfile_v1_deps(deps, violations, prefix=""):
    if not isinstance(deps, dict):
        return
    for name, meta in deps.items():
        p = f"{prefix}/{name}" if prefix else name
        if not isinstance(meta, dict):
            continue
        ver = meta.get("version")
        if isinstance(ver, str) and _npm_version_violates_lock_policy(ver):
            violations.append((p, ver))
        nested = meta.get("dependencies")
        if nested:
            _walk_lockfile_v1_deps(nested, violations, p)


def collect_npm_lock_violations(repo_dir="."):
    """Return (violations_pkg, violations_lock) for package.json / package-lock.json under repo_dir."""
    dep_keys = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    )
    violations_pkg = []
    pkg_json = os.path.join(repo_dir, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ npm lock policy: could not read package.json: {e}")
        else:
            for key in dep_keys:
                block = data.get(key)
                if not isinstance(block, dict):
                    continue
                for pkg, ver in block.items():
                    if isinstance(ver, str) and _npm_version_violates_lock_policy(ver):
                        violations_pkg.append((f"{key}.{pkg}", ver))
            _check_overrides_values(data.get("overrides"), violations_pkg)

    violations_lock = []
    lock_json = os.path.join(repo_dir, "package-lock.json")
    if os.path.exists(lock_json):
        try:
            with open(lock_json, encoding="utf-8") as f:
                lock = json.load(f)
        except Exception as e:
            print(f"⚠️ npm lock policy: could not read package-lock.json: {e}")
        else:
            for pkg_path, meta in lock.get("packages", {}).items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if isinstance(ver, str) and _npm_version_violates_lock_policy(ver):
                    label = pkg_path or "(root)"
                    violations_lock.append((label, ver))
            if lock.get("dependencies"):
                _walk_lockfile_v1_deps(lock["dependencies"], violations_lock)

    return violations_pkg, violations_lock


def check_npm_lock_policy():
    """Flag non-exact npm versions (ranges, tags, wildcards) in package.json / package-lock.json."""
    violations_pkg, violations_lock = collect_npm_lock_violations(".")

    print("\n🔒 npm lock policy (exact versions only; no ranges, tags, or wildcards)...")
    if not violations_pkg and not violations_lock:
        print("✅ No unpinned semver ranges in package.json / package-lock.json")
        return
    if violations_pkg:
        print("⚠️ package.json: non-exact or range version:")
        for where, ver in violations_pkg:
            print(f"   - {where}: {ver}")
        add_security_issue("npm-lock-policy", "Unpinned dependencies", 
                          f"Found {len(violations_pkg)} unpinned versions in package.json")
    if violations_lock:
        print("⚠️ package-lock.json: non-exact or range version:")
        for where, ver in violations_lock:
            print(f"   - {where}: {ver}")
        add_security_issue("npm-lock-policy", "Unpinned dependencies", 
                          f"Found {len(violations_lock)} unpinned versions in package-lock.json")


def main():

    # 📂 path del repo (default: current dir)
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."

    if not os.path.isdir(repo_path):
        print(f"❌ Invalid path: {repo_path}")
        return

    # 👇 moverse al root del repo
    os.chdir(repo_path)

    print(f"📁 Scanning repo: {os.getcwd()}")

    print("\n🚀 Starting security scan...\n")

    # Check npm lock policy
    if CONFIG["npm_lock_policy"] and (os.path.exists("package.json") or os.path.exists("package-lock.json")):
        check_npm_lock_policy()

    # 1. Secrets
    if CONFIG["gitleaks"]:
        if command_exists("gitleaks"):
            result = run_command(
                "gitleaks git -v --no-banner --report-format json --report-path gitleaks-report.json",
                "Scanning for secrets"
            )
            # Show leak details if any were found
            if result and result.returncode != 0:
                if os.path.exists("gitleaks-report.json"):
                    try:
                        with open("gitleaks-report.json", "r", encoding="utf-8") as f:
                            data = json.load(f)
                        leaks = data if isinstance(data, list) else data.get("leaks", [])
                        if leaks:
                            print(f"\n🚨 {len(leaks)} leak(s) found:")
                            leak_details = []
                            for leak in leaks:
                                commit = leak.get("commit", "unknown")
                                file = leak.get("file", "unknown")
                                line = leak.get("line", "unknown")
                                rule = leak.get("rule", "unknown")
                                print(f"   - Commit: {commit}")
                                print(f"     File: {file}:{line}")
                                print(f"     Rule: {rule}")
                                print()
                                leak_details.append(f"{file}:{line} ({rule})")
                            add_security_issue("gitleaks", "Secrets leaked", 
                                              f"Found {len(leaks)} potential secrets: {', '.join(leak_details[:3])}")
                    except Exception as e:
                        print(f"⚠️ Could not read gitleaks report: {e}")
                    # Clean up report file
                    try:
                        os.remove("gitleaks-report.json")
                    except:
                        pass
        else:
            print("⚠️ gitleaks not installed")

    # 2. Static analysis
    if CONFIG["semgrep"]:
        if command_exists("semgrep"):
            # Try with simple config first to isolate the issue
            print(f"🔍 Running Semgrep (auto config only)...")
            try:
                cmd = ["semgrep", "scan", "--config", "auto", "--json", "--output", "semgrep-results.json"]
                print(f"   Command: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    check=False,
                    env=os.environ,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                )
                if result.stdout.strip():
                    print(result.stdout)
                if result.stderr.strip():
                    print(result.stderr)
                if result.returncode != 0:
                    print(f"⚠️ Semgrep exited with code {result.returncode}")
                    # Try with shell=True as fallback
                    print("   Retrying with shell=True...")
                    result2 = subprocess.run(
                        "semgrep scan --config auto --json --output semgrep-results.json",
                        shell=True,
                        check=False,
                        env=os.environ,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                    )
                    if result2.stdout.strip():
                        print(result2.stdout)
                    if result2.stderr.strip():
                        print(result2.stderr)
                    if result2.returncode != 0:
                        print(f"⚠️ Semgrep (shell=True) exited with code {result2.returncode}")
            except Exception as e:
                print(f"⚠️ Error running Semgrep: {e}")
            # Always show a concise Semgrep summary (or indicate missing results file)
            print_semgrep_summary("semgrep-results.json")
        else:
            print("⚠️ semgrep not installed")

    # 3. Python deps
    if CONFIG["pip_audit"]:
        if os.path.exists("requirements.txt"):
            if command_exists("pip-audit"):
                result1 = run_command(
                    "pip-audit -r requirements.txt",
                    "Auditing Python dependencies from requirements.txt",
                )
                result2 = run_command("pip-audit", "Auditing Python dependencies")
                # Check if pip-audit found vulnerabilities
                if result1 and result1.returncode != 0:
                    add_security_issue("pip-audit", "Python vulnerabilities", 
                                      "Vulnerabilities found in Python dependencies")
                    print("💡 Tip: Use 'pipdeptree' to identify which main dependency is causing the vulnerability")
                if result2 and result2.returncode != 0:
                    add_security_issue("pip-audit", "Python vulnerabilities", 
                                      "Vulnerabilities found in Python environment")
                    print("💡 Tip: Use 'pipdeptree' to identify which main dependency is causing the vulnerability")
            else:
                print("⚠️ pip-audit not installed")

    # 4. Node deps
    if CONFIG["npm_audit"]:
        if os.path.exists("package.json"):
            if command_exists("npm"):
                result = run_command("npm audit", "Auditing npm dependencies")
                # Check if npm audit found vulnerabilities
                if result and result.returncode != 0:
                    add_security_issue("npm-audit", "Node vulnerabilities", 
                                      "Vulnerabilities found in npm dependencies")
            else:
                print("⚠️ npm not installed")

    # 5. Trivy
    if CONFIG["trivy"]:
        if command_exists("trivy"):
            result = run_command("trivy fs .", "Running Trivy filesystem scan")
            # Check if trivy found vulnerabilities
            if result and result.returncode != 0:
                add_security_issue("trivy", "Filesystem vulnerabilities", 
                                  "Vulnerabilities found in filesystem scan")
        else:
            print("⚠️ trivy not installed")

    print("\n✅ Scan completed")

    # Send email notification if issues were found
    send_email_notification(repo_path)

    # 6. Recommendations
    print("npm recomendations:")
    print("don't use npm audit fix or npm install, use npm ci to install only the desired dependencies")
    print("use docker to install dependencies and to run the project")
    print("lock de dependencies in the package.json file and the package-lock.json file to prevent chain-supply risks")
    print(f"update the dependencies manually if necessary, run npm view <package_name> versions to see the latest version")
if __name__ == "__main__":
    main()
