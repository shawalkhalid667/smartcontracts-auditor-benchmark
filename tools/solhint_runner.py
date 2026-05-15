#!/usr/bin/env python3
"""
solhint_runner.py

Runs Solhint on SmartBugs-Curated-like dataset and writes raw JSON outputs per contract.

Default:
- Contracts:  dataset/smartbugs_curated/**/*.sol
- Config:     tools/configs/solhint.json
- Outputs:    results/solhint/<contract_stem>.json   (flat unless dataset has folders)

Optional:
- --evaluate: also evaluates recall vs SmartBugs vulnerabilities.json

Additions in this version:
- Findings Summary (totals + averages) written to disk
- Precision/F1 evaluation (overall + per-category)
- Normalized finding export: normalized_findings.jsonl
- Predicted category export: predicted_categories.jsonl
"""

import argparse
import csv
import json
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any


# ---------------- Rule -> Category Mapping ----------------
SOLHINT_RULE_TO_CATEGORY: Dict[str, str] = {
    "avoid-low-level-calls": "unchecked_low_level_calls",
    "avoid-call-value": "unchecked_low_level_calls",
    "not-rely-on-time": "time_manipulation",
    "reentrancy": "reentrancy",
    # Add carefully as needed:
    # "avoid-tx-origin": "access_control",
}

SMARTBUGS_CATEGORIES = [
    "unchecked_low_level_calls",
    "time_manipulation",
    "bad_randomness",
    "denial_of_service",
    "front_running",
    "access_control",
    "short_addresses",
    "reentrancy",
    "arithmetic",
    "other",
]
# sort by length desc so "unchecked_low_level_calls_" matches before "unchecked_"
SMARTBUGS_CATEGORIES_SORTED = sorted(SMARTBUGS_CATEGORIES, key=len, reverse=True)


# ---------------- Utilities ----------------

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


def safe_write_text(p: Path, txt: str) -> None:
    p.write_text(txt, encoding="utf-8", errors="ignore")


def infer_category_from_filename(stem: str) -> Optional[str]:
    """
    Dataset is flat with filename prefixes like:
      access_control_Foo.sol
      unchecked_low_level_calls_Bar.sol
    """
    for cat in SMARTBUGS_CATEGORIES_SORTED:
        prefix = cat + "_"
        if stem.startswith(prefix):
            return cat
    return None


def strip_category_prefix(stem: str) -> str:
    """
    access_control_Foo -> Foo
    unchecked_low_level_calls_0xABC -> 0xABC
    If no known category prefix, returns stem unchanged.
    """
    cat = infer_category_from_filename(stem)
    if not cat:
        return stem
    return stem[len(cat) + 1 :]


def _extract_json_array_from_stdout(stdout: str) -> Optional[str]:
    """
    Solhint -f json should output a JSON array, but plugins/rules may print debug spam before it.
    Extract by first '[' and last ']'.
    """
    if not stdout:
        return None
    i = stdout.find("[")
    j = stdout.rfind("]")
    if i == -1 or j == -1 or j < i:
        return None
    candidate = stdout[i : j + 1]
    try:
        data = json.loads(candidate)
        if isinstance(data, list):
            return candidate
    except Exception:
        return None
    return None


def _solhint_cmd(
    solhint_bin: str,
    contract_path: Path,
    config_path: Path,
    use_output_file: bool,
    out_file: Optional[Path],
) -> List[str]:
    cmd = [
        solhint_bin,
        "-c", str(config_path),
        "-f", "json",
        str(contract_path),
    ]
    if use_output_file and out_file is not None:
        cmd.extend(["-o", str(out_file)])
    return cmd


def run_solhint(
    contract_path: Path,
    config_path: Path,
    solhint_bin: str = "solhint",
    timeout_s: Optional[int] = None,
    prefer_output_file: bool = True,
) -> Tuple[bool, str, str, int]:
    """
    Returns (ok, json_text, stderr, returncode)
    ok=True if a valid JSON array is produced (from -o file if supported, else stdout extraction).
    """
    if prefer_output_file:
        with tempfile.TemporaryDirectory() as td:
            tmp_out = Path(td) / "solhint.json"
            cmd = _solhint_cmd(solhint_bin, contract_path, config_path, True, tmp_out)
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
                err = res.stderr or ""
                if tmp_out.exists():
                    txt = safe_read_text(tmp_out).strip()
                    try:
                        data = json.loads(txt)
                        if isinstance(data, list):
                            return True, txt, err, res.returncode
                    except Exception:
                        pass
            except Exception:
                pass

    cmd = _solhint_cmd(solhint_bin, contract_path, config_path, False, None)
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    out = res.stdout or ""
    err = res.stderr or ""

    json_blob = _extract_json_array_from_stdout(out)
    if json_blob is None:
        return False, out, err, res.returncode

    try:
        data = json.loads(json_blob)
        if isinstance(data, list):
            return True, json_blob, err, res.returncode
    except Exception:
        pass
    return False, out, err, res.returncode


def solhint_counts(solhint_json_text: str) -> Tuple[int, int, int]:
    """
    Returns (findings, errors, warnings) based on the Solhint JSON output array.
    """
    try:
        issues = json.loads(solhint_json_text)
    except Exception:
        return (0, 0, 0)
    if not isinstance(issues, list):
        return (0, 0, 0)
    items = [x for x in issues if isinstance(x, dict) and "severity" in x]
    findings = len(items)
    errors = sum(1 for x in items if x.get("severity") == "Error")
    warnings = sum(1 for x in items if x.get("severity") == "Warning")
    return (findings, errors, warnings)


def parse_solhint_issues(solhint_json_text: str) -> List[Dict[str, Any]]:
    """
    Returns list of issue dicts (best effort).
    """
    try:
        issues = json.loads(solhint_json_text)
    except Exception:
        return []
    if not isinstance(issues, list):
        return []
    out: List[Dict[str, Any]] = []
    for it in issues:
        if isinstance(it, dict):
            out.append(it)
    return out


def normalize_issue(contract_stem: str, contract_rel: str, it: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a stable, tool-agnostic-ish record for downstream analysis.
    """
    rule_id = it.get("ruleId") or it.get("rule")
    severity = it.get("severity")
    message = it.get("message") or it.get("msg") or it.get("description")

    # Different solhint versions sometimes use different location keys
    line = None
    col = None

    # Common shapes:
    # - {"line": 12, "column": 3}
    # - {"location": {"line": 12, "column": 3}}
    # - {"range": [start,end]} (rare)
    if isinstance(it.get("line"), int):
        line = it.get("line")
    if isinstance(it.get("column"), int):
        col = it.get("column")

    loc = it.get("location")
    if isinstance(loc, dict):
        if line is None and isinstance(loc.get("line"), int):
            line = loc.get("line")
        if col is None and isinstance(loc.get("column"), int):
            col = loc.get("column")

    return {
        "tool": "solhint",
        "contract": contract_stem,
        "contract_relpath": contract_rel,
        "ruleId": rule_id,
        "severity": severity,
        "line": line,
        "column": col,
        "message": message,
    }


# ---------------- Ground Truth ----------------

def load_smartbugs_annotations(vuln_json: Path) -> Dict[str, Set[str]]:
    """
    Returns: contract_stem -> set(categories)
    """
    data = json.loads(safe_read_text(vuln_json))
    gt: Dict[str, Set[str]] = defaultdict(set)
    for item in data:
        name = Path(item.get("name", "")).stem
        for v in item.get("vulnerabilities", []) or []:
            cat = v.get("category")
            if name and cat:
                gt[name].add(cat)
    return gt


def extract_solhint_categories(solhint_json_text: str) -> Set[str]:
    """
    Converts Solhint findings into SmartBugs categories via SOLHINT_RULE_TO_CATEGORY mapping.
    """
    issues = parse_solhint_issues(solhint_json_text)
    cats: Set[str] = set()
    for it in issues:
        rule_id = it.get("ruleId") or it.get("rule")
        if not rule_id:
            continue
        mapped = SOLHINT_RULE_TO_CATEGORY.get(rule_id)
        if mapped:
            cats.add(mapped)
    return cats


def build_output_index(output_dir: Path) -> Dict[str, Path]:
    """
    Index outputs by multiple keys so GT naming mismatches don't break evaluation.
    For each JSON: results/solhint/<stem>.json
    We index:
      - stem
      - stripped(stem) if it starts with <category>_
    """
    idx: Dict[str, Path] = {}
    for p in output_dir.glob("*.json"):
        stem = p.stem
        idx[stem] = p
        stripped = strip_category_prefix(stem)
        idx[stripped] = p
    return idx


def pick_primary_gt_category(gt_cats: Set[str], fallback_stem: str) -> Optional[str]:
    """
    SmartBugs is 1 label per contract in your tables.
    Prefer filename prefix (if present), else if GT has exactly 1 category.
    """
    cat = infer_category_from_filename(fallback_stem)
    if cat:
        return cat
    only = [c for c in gt_cats if c in SMARTBUGS_CATEGORIES]
    if len(only) == 1:
        return only[0]
    return None


# ---------------- Precision / Recall / F1 helpers ----------------

def prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


# ---------------- Main ----------------

def main():
    repo_root = Path(__file__).resolve().parent.parent  # tools/ -> repo root

    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts-dir", default=str((repo_root / "dataset/smartbugs_curated").resolve()))
    ap.add_argument("--output-dir", default=str((repo_root / "results/solhint").resolve()))
    ap.add_argument("--config", default=str((repo_root / "tools/configs/solhint.json").resolve()))
    ap.add_argument("--solhint-bin", default="solhint")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--no-output-file", action="store_true")
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--gt", default="", help="Path to vulnerabilities.json (auto-detect if empty)")
    args = ap.parse_args()

    contracts_dir = Path(args.contracts_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    config_path = Path(args.config).resolve()

    if not contracts_dir.exists():
        raise FileNotFoundError(f"Contracts directory not found: {contracts_dir}")
    if not config_path.exists():
        raise FileNotFoundError(f"Solhint config not found: {config_path}")

    gt_candidates = [
        repo_root / "dataset/smartbugs_curated/vulnerabilities.json",
        repo_root / "dataset/smartbugs-curated/vulnerabilities.json",
    ]
    gt_path = Path(args.gt).resolve() if args.gt else next((p for p in gt_candidates if p.exists()), Path(""))

    ensure_dir(output_dir)
    failed_log = output_dir / "failed_contracts.txt"

    # New exports
    normalized_findings_path = output_dir / "normalized_findings.jsonl"
    predicted_categories_path = output_dir / "predicted_categories.jsonl"
    run_summary_json = output_dir / "run_summary.json"

    # clear previous jsonl files for clean runs
    safe_write_text(normalized_findings_path, "")
    safe_write_text(predicted_categories_path, "")

    contracts = sorted(contracts_dir.rglob("*.sol"))
    print(f"Found {len(contracts)} .sol files under {contracts_dir}")

    ok_count = 0
    fail_count = 0

    total_findings = 0
    total_errors = 0
    total_warnings = 0

    for i, c in enumerate(contracts, 1):
        stem = c.stem
        rel = str(c.relative_to(contracts_dir))
        print(f"[{i}/{len(contracts)}] {rel}")

        ok, out_json, err, rc = run_solhint(
            c,
            config_path,
            solhint_bin=args.solhint_bin,
            timeout_s=args.timeout,
            prefer_output_file=not args.no_output_file,
        )

        if not ok:
            fail_count += 1
            safe_write_text(
                output_dir / f"{stem}.raw.txt",
                f"RETURN_CODE:\n{rc}\n\nSTDOUT_OR_EXTRACT_FAIL:\n{out_json}\n\nSTDERR:\n{err}\n",
            )
            with open(failed_log, "a", encoding="utf-8") as f:
                f.write(f"{stem}: solhint output not parseable as JSON (rc={rc})\n")
            continue

        safe_write_text(output_dir / f"{stem}.json", out_json)
        ok_count += 1

        findings, errors, warnings = solhint_counts(out_json)
        total_findings += findings
        total_errors += errors
        total_warnings += warnings
        print(f"  findings: {findings} errors: {errors} warnings: {warnings}")

        # Export normalized findings
        issues = parse_solhint_issues(out_json)
        with open(normalized_findings_path, "a", encoding="utf-8") as f:
            for it in issues:
                rec = normalize_issue(stem, rel, it)
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

        # Export predicted categories (for later analysis)
        pred_cats = sorted(list(extract_solhint_categories(out_json)))
        with open(predicted_categories_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "tool": "solhint",
                "contract": stem,
                "contract_relpath": rel,
                "predicted_categories": pred_cats,
            }, ensure_ascii=False) + "\n")

    print("\n=== Solhint Run Summary ===")
    print(f"Success: {ok_count}")
    print(f"Failed:  {fail_count}")
    print(f"Outputs: {output_dir}")

    # Findings summary (your “step 2” details)
    n_contracts_total = len(contracts)
    n_contracts_ok = ok_count if ok_count else 1  # avoid div by zero
    avg_findings = total_findings / n_contracts_ok
    avg_errors = total_errors / n_contracts_ok
    avg_warnings = total_warnings / n_contracts_ok

    print("\n=== Solhint Findings Summary ===")
    print(f"Total findings: {total_findings}")
    print(f"Total errors:   {total_errors}")
    print(f"Total warnings: {total_warnings}")
    print(f"Avg findings/contract: {avg_findings:.2f}")
    print(f"Avg errors/contract:   {avg_errors:.2f}")
    print(f"Avg warnings/contract: {avg_warnings:.2f}")

    # Write run summary json
    safe_write_text(run_summary_json, json.dumps({
        "tool": "solhint",
        "contracts_total": n_contracts_total,
        "contracts_success": ok_count,
        "contracts_failed": fail_count,
        "total_findings": total_findings,
        "total_errors": total_errors,
        "total_warnings": total_warnings,
        "avg_findings_per_success_contract": round(avg_findings, 4),
        "avg_errors_per_success_contract": round(avg_errors, 4),
        "avg_warnings_per_success_contract": round(avg_warnings, 4),
        "outputs_dir": str(output_dir),
        "normalized_findings_jsonl": str(normalized_findings_path),
        "predicted_categories_jsonl": str(predicted_categories_path),
    }, indent=2))

    if not args.evaluate:
        return

    if not gt_path or not gt_path.exists():
        raise FileNotFoundError(
            "Ground truth vulnerabilities.json not found. "
            "Pass --gt /path/to/vulnerabilities.json or place it under dataset/smartbugs_curated/."
        )

    gt = load_smartbugs_annotations(gt_path)

    # Build robust output lookup
    out_index = build_output_index(output_dir)

    # ----------------
    # 1) Your existing “primary label” recall tables (kept)
    # ----------------
    total_contracts = 0
    correct = 0
    missed = 0
    error_no_output = 0
    by_cat = defaultdict(lambda: {"total": 0, "correct": 0, "missed": 0, "error": 0})

    for gt_stem, gt_cats in gt.items():
        out_file = out_index.get(gt_stem)
        if out_file is None:
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                candidate = f"{cat}_{gt_stem}"
                if candidate in out_index:
                    out_file = out_index[candidate]
                    break

        primary_cat = pick_primary_gt_category(gt_cats, gt_stem)
        if primary_cat is None:
            continue

        total_contracts += 1
        by_cat[primary_cat]["total"] += 1

        if out_file is None or not out_file.exists():
            error_no_output += 1
            by_cat[primary_cat]["error"] += 1
            continue

        detected = extract_solhint_categories(safe_read_text(out_file))
        if primary_cat in detected:
            correct += 1
            by_cat[primary_cat]["correct"] += 1
        else:
            missed += 1
            by_cat[primary_cat]["missed"] += 1

    recall_primary = (correct / (correct + missed)) if (correct + missed) else 0.0

    print("\n=== Solhint Correctness Summary ===")
    print(f"Total contracts: {total_contracts}")
    print(f"Correct detections: {correct}")
    print(f"Missed detections: {missed}")
    print(f"Errors (no output): {error_no_output}")
    print(f"Recall: {recall_primary:.2f}")

    print("=== Solhint Per-Category Results ===")
    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        r = (s["correct"] / (s["correct"] + s["missed"])) if (s["correct"] + s["missed"]) else 0.0
        print(f"{cat} Total: {s['total']} Correct: {s['correct']} Missed: {s['missed']} Error: {s['error']} Recall: {r:.2f}")

    with open(output_dir / "evaluation_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "total_contracts", "correct", "missed", "error", "recall"])
        w.writerow(["solhint", total_contracts, correct, missed, error_no_output, f"{recall_primary:.2f}"])

    with open(output_dir / "evaluation_by_category.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "category", "total", "correct", "missed", "error", "recall"])
        for cat in SMARTBUGS_CATEGORIES:
            s = by_cat[cat]
            r = (s["correct"] / (s["correct"] + s["missed"])) if (s["correct"] + s["missed"]) else 0.0
            w.writerow(["solhint", cat, s["total"], s["correct"], s["missed"], s["error"], f"{r:.2f}"])

    # ----------------
    # 2) NEW: Precision / Recall / F1 (multi-label at contract level)
    #    This treats each category as a label: predicted vs ground truth.
    # ----------------
    per_cat_counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "errors": 0})
    micro_tp = micro_fp = micro_fn = 0
    contracts_scored = 0
    contracts_error = 0

    for gt_stem, gt_cats in gt.items():
        # Only consider categories we care about
        gt_set = set([c for c in gt_cats if c in SMARTBUGS_CATEGORIES])

        # Resolve output file
        out_file = out_index.get(gt_stem)
        if out_file is None:
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                candidate = f"{cat}_{gt_stem}"
                if candidate in out_index:
                    out_file = out_index[candidate]
                    break

        if out_file is None or not out_file.exists():
            # treat as an error; count FN for all GT labels
            contracts_error += 1
            for c in gt_set:
                per_cat_counts[c]["fn"] += 1
                per_cat_counts[c]["errors"] += 1
                micro_fn += 1
            continue

        pred_set = extract_solhint_categories(safe_read_text(out_file))
        # Only evaluate categories in our taxonomy
        pred_set = set([c for c in pred_set if c in SMARTBUGS_CATEGORIES])

        contracts_scored += 1

        # TP/FP/FN per contract
        for c in pred_set:
            if c in gt_set:
                per_cat_counts[c]["tp"] += 1
                micro_tp += 1
            else:
                per_cat_counts[c]["fp"] += 1
                micro_fp += 1

        for c in gt_set:
            if c not in pred_set:
                per_cat_counts[c]["fn"] += 1
                micro_fn += 1

    micro_p, micro_r, micro_f1 = prf(micro_tp, micro_fp, micro_fn)

    print("\n=== Solhint Precision/Recall/F1 (Category Labels) ===")
    print(f"Contracts scored: {contracts_scored}")
    print(f"Contracts missing output: {contracts_error}")
    print(f"Micro-TP: {micro_tp}  Micro-FP: {micro_fp}  Micro-FN: {micro_fn}")
    print(f"Micro-Precision: {micro_p:.2f}")
    print(f"Micro-Recall:    {micro_r:.2f}")
    print(f"Micro-F1:        {micro_f1:.2f}")

    print("=== Solhint Per-Category Precision/Recall/F1 ===")
    for cat in SMARTBUGS_CATEGORIES:
        tp = per_cat_counts[cat]["tp"]
        fp = per_cat_counts[cat]["fp"]
        fn = per_cat_counts[cat]["fn"]
        p, r, f1 = prf(tp, fp, fn)
        print(f"{cat} TP:{tp} FP:{fp} FN:{fn}  P:{p:.2f} R:{r:.2f} F1:{f1:.2f}")

    # Write precision outputs
    with open(output_dir / "precision_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "micro_tp", "micro_fp", "micro_fn", "micro_precision", "micro_recall", "micro_f1", "contracts_scored", "contracts_missing_output"])
        w.writerow(["solhint", micro_tp, micro_fp, micro_fn, f"{micro_p:.4f}", f"{micro_r:.4f}", f"{micro_f1:.4f}", contracts_scored, contracts_error])

    with open(output_dir / "precision_by_category.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "category", "tp", "fp", "fn", "precision", "recall", "f1", "errors_missing_output"])
        for cat in SMARTBUGS_CATEGORIES:
            tp = per_cat_counts[cat]["tp"]
            fp = per_cat_counts[cat]["fp"]
            fn = per_cat_counts[cat]["fn"]
            errs = per_cat_counts[cat]["errors"]
            p, r, f1 = prf(tp, fp, fn)
            w.writerow(["solhint", cat, tp, fp, fn, f"{p:.4f}", f"{r:.4f}", f"{f1:.4f}", errs])


if __name__ == "__main__":
    main()
