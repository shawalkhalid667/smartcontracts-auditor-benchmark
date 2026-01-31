import json
import subprocess
from pathlib import Path

VERSION_DIR = Path("../dataset/versions")

def load_required_versions():
    versions = set()
    for file in VERSION_DIR.glob("*.json"):
        with open(file) as f:
            data = json.load(f)
            ver = data.get("solc_version")
            if ver:
                versions.add(ver)
    return sorted(versions)

def install_version(version):
    print(f"Installing solc version: {version}")
    try:
        subprocess.run(["solc-select", "install", version], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install {version}: {e}")

def main():
    versions = load_required_versions()
    print(f"Found {len(versions)} versions to install: {versions}")
    for ver in versions:
        install_version(ver)

if __name__ == "__main__":
    main()
