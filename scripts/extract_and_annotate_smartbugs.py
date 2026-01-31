import os
import json
from pathlib import Path
import shutil

RAW_DIR = Path("../dataset/smartbugs-curated")
FLAT_DIR = Path("../dataset/smartbugs_curated")
ANNOTATION_DIR = Path("../dataset/annotations")

FLAT_DIR.mkdir(parents=True, exist_ok=True)
ANNOTATION_DIR.mkdir(parents=True, exist_ok=True)

def flatten_and_annotate():
    for root, _, files in os.walk(RAW_DIR):
        for file in files:
            if file.endswith(".sol"):
                vuln_type = Path(root).parts[-1]  # use folder name as label
                src_path = Path(root) / file
                flat_filename = f"{vuln_type}_{file}"
                dst_path = FLAT_DIR / flat_filename
                shutil.copy(src_path, dst_path)

                annotation = {
                    "contract": flat_filename,
                    "vulnerabilities": [
                        {"type": vuln_type.replace("_", " "), "line": None, "severity": "unknown"}
                    ]
                }

                with open(ANNOTATION_DIR / f"{flat_filename.replace('.sol', '.json')}", "w") as f:
                    json.dump(annotation, f, indent=2)
                print(f"[✓] {flat_filename} extracted with annotation")

if __name__ == "__main__":
    flatten_and_annotate()
