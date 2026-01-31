import json
import subprocess
import re
import csv
from pathlib import Path
from slither_check_mapping import categorize  # <-- only need categorize

# === Path Configurations ===
SMARTBUG_ROOT = Path("../dataset/smartbugs-curated")
VULN_JSON = SMARTBUG_ROOT / "vulnerabilities.json"
CONTRACTS_DIR = SMARTBUG_ROOT / "dataset"
VERSIONS_DIR = Path("../dataset/versions")
SLITHER_RESULTS_DIR = Path("../results/slither")

# Will be populated from vulnerabilities.json
CONTRACT_PRAGMAS = {}


# === Version Utilities ===
def parse_version_from_pragma(pragma_str):
    match = re.search(r"\d+\.\d+\.\d+", pragma_str or "")
    return match.group(0) if match else "0.4.24"


def ensure_solc_version(contract_name):
    """
    Prefer pragma from vulnerabilities.json (CONTRACT_PRAGMAS).
    Fall back to legacy versions/*.json if present.
    Otherwise use default 0.4.24.
    """
    pragma = CONTRACT_PRAGMAS.get(contract_name)
    if pragma:
        version = parse_version_from_pragma(pragma)
    else:
        version_file = VERSIONS_DIR / f"{contract_name}.json"
        if version_file.exists():
            with version_file.open() as f:
                data = json.load(f)
                version = parse_version_from_pragma(
                    data.get("pragma", "pragma solidity ^0.4.24;")
                )
        else:
            print(f"[!] Missing pragma info for {contract_name}, using default 0.4.24")
            version = "0.4.24"

    subprocess.run(["solc-select", "install", version], check=False)
    try:
        subprocess.run(["solc-select", "use", version], check=True)
    except subprocess.CalledProcessError:
        print(f"[!] Failed to use solc version {version}")
        return False
    return True


# === Annotation Loader (from vulnerabilities.json) ===
def load_annotations():
    """
    Load ground-truth vulnerabilities from SmartBugs' vulnerabilities.json.

    Returns:
      gt: dict[contract_stem -> set[(category, line)]]
    Also populates global CONTRACT_PRAGMAS[contract_stem] = pragma string.
    """
    global CONTRACT_PRAGMAS
    CONTRACT_PRAGMAS = {}

    gt = {}
    if not VULN_JSON.exists():
        raise FileNotFoundError(f"Ground-truth file not found: {VULN_JSON}")

    with VULN_JSON.open() as f:
        data = json.load(f)

    for entry in data:
        name = entry.get("name")
        if not name:
            continue
        contract_stem = Path(name).stem

        pragma = entry.get("pragma")
        CONTRACT_PRAGMAS[contract_stem] = pragma

        vulns = entry.get("vulnerabilities", [])
        if not vulns:
            continue

        if contract_stem not in gt:
            gt[contract_stem] = set()

        for vuln in vulns:
            category = vuln.get("category")
            lines = vuln.get("lines", [])
            if not category:
                continue
            for line in lines:
                if isinstance(line, int):
                    gt[contract_stem].add((category, line))

    return gt


# === File Search ===
def find_contract_file(contract_name):
    for sol_file in CONTRACTS_DIR.rglob("*.sol"):
        if sol_file.stem == contract_name:
            return sol_file
    return None


# === Run Slither ===
def run_slither_if_missing(contract_name):
    output_file = SLITHER_RESULTS_DIR / f"{contract_name}.json"

    if output_file.exists() and output_file.stat().st_size > 500:
        return

    contract_file = find_contract_file(contract_name)
    if not contract_file:
        print(f"[!] Contract source not found for {contract_name}")
        return

    if not ensure_solc_version(contract_name):
        return

    try:
        result = subprocess.run(
            ["slither", str(contract_file), "--json", str(output_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
        )
        if result.returncode != 0:
            if not output_file.exists() or output_file.stat().st_size < 500:
                print(f"[!] Slither failed on {contract_name}: {result.stderr.decode()[:200]}")
    except subprocess.TimeoutExpired:
        print(f"[X] Timeout while running Slither on {contract_name}")


# === Parse Slither Output ===
def load_slither_output(file):
    """
    Returns:
      gt_findings:   set[(smartbugs_category, line)]
      oor_security:  set[(raw_detector_name, line)]
      oor_noise:     int  (count of noise findings)
    """
    with file.open() as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] JSON parse error in {file}")
            return set(), set(), 0

        gt_findings = set()
        oor_security = set()
        oor_noise = 0

        detectors = data.get("results", {}).get("detectors", [])
        for detector in detectors:
            raw_type = detector.get("check")
            dtype, label = categorize(raw_type)

            for elem in detector.get("elements", []):
                lines = elem.get("source_mapping", {}).get("lines", [])
                for line in lines:
                    if not isinstance(line, int):
                        continue

                    if dtype == "GT":
                        gt_findings.add((label, line))
                    elif dtype == "OOR_SECURITY":
                        oor_security.add((raw_type, line))
                    else:
                        oor_noise += 1

        return gt_findings, oor_security, oor_noise


# === Evaluation Logic ===
def line_match(pred_line, gt_line, tolerance=2):
    return (
        isinstance(pred_line, int)
        and isinstance(gt_line, int)
        and abs(pred_line - gt_line) <= tolerance
    )


def evaluate(ground_truth, predicted):
    """
    Both sets:
       set[(category, line)]

    Returns:
      precision, recall, f1, tp, fp, fn, matched_gt, matched_pred
    """
    tp = 0
    matched_gt = set()
    matched_pred = set()

    for pred_item in predicted:
        pred_type, pred_line = pred_item
        for gt_item in ground_truth:
            gt_type, gt_line = gt_item
            if pred_type == gt_type and line_match(pred_line, gt_line):
                tp += 1
                matched_gt.add(gt_item)
                matched_pred.add(pred_item)
                break

    fp = len(predicted - matched_pred)
    fn = len(ground_truth - matched_gt)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return precision, recall, f1, tp, fp, fn, matched_gt, matched_pred


# === CSV Writers ===
def save_results_to_csv(results):
    out_path = SLITHER_RESULTS_DIR / "evaluation_summary.csv"
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Contract",
                "Precision",
                "Recall",
                "F1",
                "TP",
                "FP",
                "FN",
                "OOR_Security",
                "Noise_Count",
            ]
        )
        writer.writerows(results)
    print(f"[✓] Saved summary to {out_path}")


def save_category_results_to_csv(category_totals):
    out_path = SLITHER_RESULTS_DIR / "category_summary.csv"
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Precision", "Recall", "F1", "TP", "FP", "FN"])
        for cat, stats in sorted(category_totals.items()):
            tp = stats["tp"]
            fp = stats["fp"]
            fn = stats["fn"]
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            writer.writerow([cat, precision, recall, f1, tp, fp, fn])
    print(f"[✓] Saved per-category summary to {out_path}")


def save_extra_security_to_csv(extra_security_by_contract):
    out_path = SLITHER_RESULTS_DIR / "extra_findings.csv"
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Contract", "Detector", "Line"])
        for contract, findings in sorted(extra_security_by_contract.items()):
            for detector_name, line in sorted(findings, key=lambda x: (x[0], x[1])):
                writer.writerow([contract, detector_name, line])
    print(f"[✓] Saved extra (out-of-scope) security findings to {out_path}")


# === Main ===
def main():
    SLITHER_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    annotations = load_annotations()

    total_tp = total_fp = total_fn = 0
    total_oor_security = 0
    total_noise = 0

    results = []
    category_totals = {}
    extra_security_by_contract = {}

    for i, contract_name in enumerate(sorted(annotations.keys())):
        print(f"\n[{i+1}/{len(annotations)}] Evaluating {contract_name}...")

        run_slither_if_missing(contract_name)
        json_file = SLITHER_RESULTS_DIR / f"{contract_name}.json"
        if not json_file.exists():
            print(f"[!] Missing Slither result for {contract_name}")
            continue

        ground_truth = annotations[contract_name]

        predicted, extra_security, noise_count = load_slither_output(json_file)

        precision, recall, f1, tp, fp, fn, matched_gt, matched_pred = evaluate(
            ground_truth, predicted
        )

        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_oor_security += len(extra_security)
        total_noise += noise_count

        if extra_security:
            extra_security_by_contract[contract_name] = extra_security

        results.append(
            [
                contract_name,
                precision,
                recall,
                f1,
                tp,
                fp,
                fn,
                len(extra_security),
                noise_count,
            ]
        )

        print(
            f"{contract_name}: P={precision:.2f}, R={recall:.2f}, "
            f"F1={f1:.2f}, TP={tp}, FP={fp}, FN={fn}"
        )
        print(
            f"    [+] OOR security findings (not scored): {len(extra_security)}, "
            f"noise warnings: {noise_count}"
        )

        # --- Update per-category stats ---
        for gt_item in ground_truth:
            gt_cat, _ = gt_item
            if gt_cat not in category_totals:
                category_totals[gt_cat] = {"tp": 0, "fp": 0, "fn": 0}
            if gt_item in matched_gt:
                category_totals[gt_cat]["tp"] += 1
            else:
                category_totals[gt_cat]["fn"] += 1

        for pred_item in predicted:
            pred_cat, _ = pred_item
            if pred_cat not in category_totals:
                category_totals[pred_cat] = {"tp": 0, "fp": 0, "fn": 0}
            if pred_item not in matched_pred:
                category_totals[pred_cat]["fp"] += 1

    print("\n==== Overall ====")
    overall_precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 0.0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall)
        else 0.0
    )

    print(f"Processed {len(annotations)} contracts.")
    print(f"Total TP={total_tp}, FP={total_fp}, FN={total_fn}")
    print(f"Precision: {overall_precision:.2f}")
    print(f"Recall:    {overall_recall:.2f}")
    print(f"F1 Score:  {overall_f1:.2f}")
    print(f"OOR security findings (not scored): {total_oor_security}")
    print(f"Noise warnings (ignored): {total_noise}")

    save_results_to_csv(results)
    save_category_results_to_csv(category_totals)
    save_extra_security_to_csv(extra_security_by_contract)


if __name__ == "__main__":
    main()
