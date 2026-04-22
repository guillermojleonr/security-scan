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
    if violations_lock:
        print("⚠️ package-lock.json: non-exact or range version:")
        for where, ver in violations_lock:
            print(f"   - {where}: {ver}")


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
    if os.path.exists("package.json") or os.path.exists("package-lock.json"):
        check_npm_lock_policy()

    # 1. Secrets
    if command_exists("gitleaks"):
        run_command("gitleaks detect --no-banner", "Scanning for secrets")
    else:
        print("⚠️ gitleaks not installed")

    # 2. Static analysis
    if command_exists("semgrep"):
        # Build absolute path to custom rules file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        custom_rules = os.path.join(script_dir, "rules", "invisible-unicode.yml")
        
        if os.path.exists(custom_rules):
            # Run Semgrep with both the default config and custom invisible-unicode rules
            result = run_command(
                f'semgrep scan --config auto --config "{custom_rules}" --json --output semgrep-results.json',
                "Running Semgrep (combined configs, JSON output)",
            )
        else:
            # Fallback: run without custom rules
            print(f"⚠️ Custom rules file not found: {custom_rules}")
            print("   Running Semgrep with auto config only...")
            result = run_command(
                "semgrep scan --config auto --json --output semgrep-results.json",
                "Running Semgrep (auto config only)",
            )
        # Always show a concise Semgrep summary (or indicate missing results file)
        print_semgrep_summary("semgrep-results.json")

    else:
        print("⚠️ semgrep not installed")

    # 3. Python deps
    if os.path.exists("requirements.txt"):
        if command_exists("pip-audit"):
            run_command(
                "pip-audit -r requirements.txt",
                "Auditing Python dependencies from requirements.txt",
            )
            run_command("pip-audit", "Auditing Python dependencies")
        else:
            print("⚠️ pip-audit not installed")

    # 4. Node deps
    if os.path.exists("package.json"):
        if command_exists("npm"):
            run_command("npm audit", "Auditing npm dependencies")
        else:
            print("⚠️ npm not installed")

    # 5. Trivy
    if command_exists("trivy"):
        run_command("trivy fs .", "Running Trivy filesystem scan")
    else:
        print("⚠️ trivy not installed")

    print("\n✅ Scan completed")

    # 6. Recommendations
    print("npm recomendations:")
    print("don't use npm audit fix or npm install, use npm ci to install only the desired dependencies")
    print("use docker to install dependencies and to run the project")
    print("lock de dependencies in the package.json file and the package-lock.json file to prevent chain-supply risks")
    print(f"update the dependencies manually if necessary, run npm view <package_name> versions to see the latest version")
if __name__ == "__main__":
    main()
