import re
import os
import json
from pathlib import Path

DATASET_DIR = Path("../dataset/smartbugs_curated")
OUTPUT_DIR = Path("../dataset/versions")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

pragma_regex = re.compile(r"pragma\s+solidity\s+[^;]+;")

def extract_solc_version(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = pragma_regex.search(line)
            if match:
                return match.group(0).strip()
    return "pragma not found"

def main():
    for file in DATASET_DIR.glob("**/*.sol"):
        version = extract_solc_version(file)
        version_info = {"contract": file.name, "pragma": version}
        out_path = OUTPUT_DIR / (file.stem + ".json")
        with open(out_path, "w") as f:
            json.dump(version_info, f, indent=2)
        print(f"[✓] {file.name}: {version}")

if __name__ == "__main__":
    main()
