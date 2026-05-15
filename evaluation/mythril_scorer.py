# mythril_scorer.py

import json
import csv
from pathlib import Path

from mythril_check_mapping import categorize

SMARTBUG_ROOT = Path("../dataset/smartbugs-curated")
VULN_JSON = SMARTBUG_ROOT / "vulnerabilities.json"
CONTRACTS_DIR = SMARTBUG_ROOT / "dataset"

MYTHRIL_RESULTS_ROOT = Path("../results/mythril")


# ---------- Ground truth loader (same semantics as Slither scorer) ----------

def load_annotations():
    """
    Load ground-truth vulnerabilities from SmartBugs' vulnerabilities.json.

    Returns:
      gt: dict[contract_stem -> set[(category, line)]]
    """
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


def find_contract_file(contract_name: str):
    """
    Find a .sol file whose stem matches contract_name anywhere under CONTRACTS_DIR.
    """
    for sol_file in CONTRACTS_DIR.rglob("*.sol"):
        if sol_file.stem == contract_name:
            return sol_file
    return None


# ---------- Offset → line helpers ----------

def build_newline_positions(text: str):
    """
    Return a list of indices where '\n' occurs.
    """
    return [i for i, ch in enumerate(text) if ch == "\n"]


def offset_to_line(offset: int, newline_positions):
    """
    Convert a character offset (0-based) to a 1-based line number.
    We count how many newline chars occur before offset.
    """
    line = 1
    for pos in newline_positions:
        if pos < offset:
            line += 1
        else:
            break
    return line


# ---------- Mythril JSON parsing ----------

def parse_mythril_output(json_file: Path, contract_file: Path):
    """
    Parse Mythril JSON and map its SWC issues to SmartBugs categories
    using mythril_check_mapping.categorize().

    Returns:
      gt_findings: set[(category, line)]
      oor_security: set[(swc_id, line)]
      noise_count: int
    """
    if not json_file.exists():
        return set(), set(), 0

    try:
        with json_file.open() as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[!] JSON parse error in {json_file}")
        return set(), set(), 0

    try:
        src_text = contract_file.read_text()
    except FileNotFoundError:
        print(f"[!] Contract source missing for {contract_file}")
        return set(), set(), 0

    newline_positions = build_newline_positions(src_text)

    gt_findings = set()
    oor_security = set()
    noise_count = 0

    for issue in data.get("issues", []):
        swc_id = issue.get("swc-id", "")
        title = issue.get("title", "") or issue.get("description", {}).get("head", "")

        dtype, label = categorize(swc_id, title)

        locations = issue.get("locations", [])
        if not locations:
            # Some issues may not have explicit locations
            if dtype == "NOISE":
                noise_count += 1
            else:
                # security-ish but no location - we can't score lines, just count as noise-like
                noise_count += 1
            continue

        for loc in locations:
            srcmap = loc.get("sourceMap") or loc.get("source_map")
            if not srcmap:
                continue

            # sourceMap has format "start:length:fileIndex"
            start_str = srcmap.split(":", 1)[0]
            try:
                start = int(start_str)
            except ValueError:
                continue

            line = offset_to_line(start, newline_positions)

            if dtype == "GT":
                gt_findings.add((label, line))
            elif dtype == "OOR_SECURITY":
                oor_security.add((swc_id, line))
            else:
                noise_count += 1

    return gt_findings, oor_security, noise_count


# ---------- Evaluation ----------

def line_match(pred_line, gt_line, tolerance=2):
    return (
        isinstance(pred_line, int)
        and isinstance(gt_line, int)
        and abs(pred_line - gt_line) <= tolerance
    )


def evaluate(ground_truth, predicted):
    """
    Both arguments are sets of (category, line).

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


# ---------- CSV writers ----------

def save_results_to_csv(results, out_path: Path):
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Contract", "Precision", "Recall", "F1", "TP", "FP", "FN"])
        writer.writerows(results)
    print(f"[✓] Saved summary to {out_path}")


def save_category_results_to_csv(category_totals, out_path: Path):
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


# ---------- Main scoring for both modes ----------

def score_mode(mode: str, annotations):
    mode_root = MYTHRIL_RESULTS_ROOT / mode
    raw_dir = mode_root / "raw"

    if not raw_dir.exists():
        print(f"[!] Raw directory for mode '{mode}' not found at {raw_dir}. Skipping.")
        return

    total_tp = total_fp = total_fn = 0
    total_oor_security = 0
    total_noise = 0
    results = []
    category_totals = {}

    print(f"\n==== Mythril ({mode}) ====")

    for i, contract_name in enumerate(sorted(annotations.keys())):
        json_file = raw_dir / f"{contract_name}.json"
        if not json_file.exists():
            print(f"[!] Missing Mythril result for {contract_name} in mode {mode}")
            continue

        contract_file = find_contract_file(contract_name)
        if not contract_file:
            print(f"[!] Contract file not found for {contract_name}")
            continue

        ground_truth = annotations[contract_name]  # set[(cat, line)]
        predicted, oor_security, noise_count = parse_mythril_output(json_file, contract_file)

        precision, recall, f1, tp, fp, fn, matched_gt, matched_pred = evaluate(
            ground_truth, predicted
        )

        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_oor_security += len(oor_security)
        total_noise += noise_count

        results.append([contract_name, precision, recall, f1, tp, fp, fn])

        print(
            f"[{i+1}/{len(annotations)}] {contract_name}: "
            f"P={precision:.2f}, R={recall:.2f}, F1={f1:.2f}, "
            f"TP={tp}, FP={fp}, FN={fn}"
        )

        # --- Update per-category stats from GT categories ---
        for gt_item in ground_truth:
            gt_cat, _ = gt_item
            if gt_cat not in category_totals:
                category_totals[gt_cat] = {"tp": 0, "fp": 0, "fn": 0}
            if gt_item in matched_gt:
                category_totals[gt_cat]["tp"] += 1
            else:
                category_totals[gt_cat]["fn"] += 1

        # --- Count FP per predicted category ---
        for pred_item in predicted:
            pred_cat, _ = pred_item
            if pred_cat not in category_totals:
                category_totals[pred_cat] = {"tp": 0, "fp": 0, "fn": 0}
            if pred_item not in matched_pred:
                category_totals[pred_cat]["fp"] += 1

    # Overall metrics
    overall_precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 0.0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall)
        else 0.0
    )

    print("\n---- Summary ----")
    print(f"Processed {len(annotations)} contracts (mode={mode}).")
    print(f"Total TP={total_tp}, FP={total_fp}, FN={total_fn}")
    print(f"Precision: {overall_precision:.2f}")
    print(f"Recall:    {overall_recall:.2f}")
    print(f"F1 Score:  {overall_f1:.2f}")
    print(f"OOR security findings (not scored): {total_oor_security}")
    print(f"Noise findings (ignored): {total_noise}")

    save_results_to_csv(results, mode_root / "evaluation_summary.csv")
    save_category_results_to_csv(category_totals, mode_root / "category_summary.csv")


def main():
    annotations = load_annotations()
    print(f"[i] Loaded ground truth for {len(annotations)} contracts.")

    for mode in ["baseline", "deep"]:
        score_mode(mode, annotations)


if __name__ == "__main__":
    main()
