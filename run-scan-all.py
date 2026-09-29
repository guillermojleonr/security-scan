import os
import subprocess
import sys

# Directorio base donde están los repos
BASE_DIR = r"C:\Users\it\dev"
# Ruta al script de security-scan
SECURITY_SCAN_SCRIPT = os.path.join(BASE_DIR, "security-scan", "security-scan.py")

def scan_repo(repo_name):
    """Ejecuta security-scan.py en un repositorio específico"""
    repo_path = os.path.join(BASE_DIR, repo_name)
    
    print(f"\n{'='*60}")
    print(f"📁 Scanning: {repo_name}")
    print(f"{'='*60}")
    
    if not os.path.isdir(repo_path):
        print(f"⚠️ No es un directorio válido: {repo_path}")
        return
    
    # Ejecutar el security-scan.py
    cmd = [sys.executable, SECURITY_SCAN_SCRIPT, repo_path]
    try:
        result = subprocess.run(cmd, check=False, env=os.environ)
        print(f"\n✅ Scan completed for {repo_name} (exit code: {result.returncode})")
    except Exception as e:
        print(f"❌ Error scanning {repo_name}: {e}")

def main():
    # Cambiar al directorio base
    os.chdir(BASE_DIR)
    
    print("🚀 Starting security scan for all repositories...")
    print(f"📂 Base directory: {BASE_DIR}")
    
    # Obtener todos los subdirectorios
    repos = [d for d in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, d))]
    
    # Excluir el directorio security-scan para no escanear el propio script
    repos = [r for r in repos if r != "security-scan"]
    
    print(f"📋 Found {len(repos)} repositories to scan")
    
    # Escanear cada repositorio
    for repo in repos:
        scan_repo(repo)
    
    print(f"\n{'='*60}")
    print("✅ Security scan completed for all repositories")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
