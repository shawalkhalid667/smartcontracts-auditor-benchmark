#!/usr/bin/env python3
"""
smartcheck_runner.py

Runs SmartCheck (SmartDec) on SmartBugs-Curated-like dataset and writes outputs per contract.

Default:
- Contracts:  dataset/smartbugs_curated/**/*.sol
- Runner:     npx smartcheck
- Outputs:    results/smartcheck/<contract_stem>.json + .raw.txt

Evaluation (--evaluate):
- Writes results/smartcheck/evaluation_common.csv with a tool-agnostic schema:
  * Failure counts (crash/empty/success)
  * Micro P/R/F1 on category labels (multi-label)
  * Coverage-aware micro P/R/F1 restricted to supported categories
  * Precision@K / Recall@K / F1@K for K in {1,3,5,10} (also coverage-aware versions)
- ALSO writes (Solhint-style) primary-label per-category recall table:
  * Console block: "Category-Level Recall (Primary Label per Contract)"
  * CSV: results/smartcheck/evaluation_primary_recall_by_category.csv
  * (optional) LaTeX: results/smartcheck/table_primary_recall.tex

Notes:
- SmartCheck prints plain-text blocks, not JSON.
- We parse blocks containing keys: ruleId, patternId, severity, line, column, content.
- Detected categories come from mapping ruleId -> SmartBugs category.
"""

import argparse
import csv
import json
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------- SmartBugs Categories ----------------
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
SMARTBUGS_CATEGORIES_SORTED = sorted(SMARTBUGS_CATEGORIES, key=len, reverse=True)

K_LIST = [1, 3, 5, 10]


# ---------------- Rule -> Category Mapping ----------------
# Keep conservative; expand as you validate mappings.
SMARTCHECK_RULE_TO_CATEGORY: Dict[str, str] = {
    "SOLIDITY_CALL_WITHOUT_DATA": "unchecked_low_level_calls",
    "SOLIDITY_UNCHECKED_CALL": "unchecked_low_level_calls",
    "SOLIDITY_SEND": "unchecked_low_level_calls",  # sometimes used similarly

    "SOLIDITY_EXACT_TIME": "time_manipulation",

    "SOLIDITY_TX_ORIGIN": "access_control",
    "SOLIDITY_OVERPOWERED_ROLE": "access_control",

    "SOLIDITY_DIV_MUL": "arithmetic",
    "SOLIDITY_SAFEMATH": "arithmetic",  # presence/absence signals arithmetic risk patterns

    "SOLIDITY_INCORRECT_BLOCKHASH": "bad_randomness",

    "SOLIDITY_GAS_LIMIT_IN_LOOPS": "denial_of_service",
    "SOLIDITY_EXTRA_GAS_IN_LOOPS": "denial_of_service",
    "SOLIDITY_TRANSFER_IN_LOOP": "denial_of_service",

    # "reentrancy": SmartCheck often doesn't have a reliable rule for classic reentrancy in practice,
    # but if you later confirm a ruleId, add it here.
}

SUPPORTED_CATEGORIES: Set[str] = set(SMARTCHECK_RULE_TO_CATEGORY.values())


# ---------------- Utilities ----------------
def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def infer_category_from_filename(stem: str) -> Optional[str]:
    for cat in SMARTBUGS_CATEGORIES_SORTED:
        if stem.startswith(cat + "_"):
            return cat
    return None


def strip_category_prefix(stem: str) -> str:
    cat = infer_category_from_filename(stem)
    if not cat:
        return stem
    return stem[len(cat) + 1:]


def run_smartcheck(
    target_path: Path,
    smartcheck_cmd: str = "npx smartcheck",
    timeout_s: Optional[int] = None,
) -> Tuple[int, str, str]:
    """
    Returns (returncode, stdout, stderr).
    """
    cmd = smartcheck_cmd.split() + ["-p", str(target_path)]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return res.returncode, (res.stdout or ""), (res.stderr or "")


# ---------------- Parsing ----------------
_RULE_BLOCK_RE = re.compile(
    r"ruleId:\s*(?P<ruleId>[A-Z0-9_]+)\s*"
    r"patternId:\s*(?P<patternId>[A-Za-z0-9_]+)\s*"
    r"severity:\s*(?P<severity>\d+)\s*"
    r"line:\s*(?P<line>\d+)\s*"
    r"column:\s*(?P<column>\d+)\s*"
    r"content:\s*(?P<content>.*?)(?=\n\s*\n|$)",
    re.DOTALL
)


def parse_smartcheck_output(stdout: str) -> List[dict]:
    findings: List[dict] = []
    for m in _RULE_BLOCK_RE.finditer(stdout):
        d = m.groupdict()
        findings.append({
            "ruleId": d["ruleId"].strip(),
            "patternId": d["patternId"].strip(),
            "severity": int(d["severity"]),
            "line": int(d["line"]),
            "column": int(d["column"]),
            "content": d["content"].strip(),
        })
    return findings


def smartcheck_counts(findings: List[dict]) -> Tuple[int, int, int]:
    """
    Count:
      - total
      - sev>=2 as errors
      - sev==1 as warnings
    """
    total = len(findings)
    errors = sum(1 for f in findings if int(f.get("severity", 0)) >= 2)
    warnings = sum(1 for f in findings if int(f.get("severity", 0)) == 1)
    return total, errors, warnings


def finding_categories(f: dict) -> Set[str]:
    rid = f.get("ruleId")
    if not rid:
        return set()
    mapped = SMARTCHECK_RULE_TO_CATEGORY.get(rid)
    return {mapped} if mapped else set()


def contract_detected_categories(findings: List[dict]) -> Set[str]:
    out: Set[str] = set()
    for f in findings:
        out |= finding_categories(f)
    return out


def contract_detected_categories_topk(findings: List[dict], k: int) -> Set[str]:
    # SmartCheck severity: higher = more severe (2 > 1). Sort desc, stable by line-ish signal.
    ordered = sorted(
        findings,
        key=lambda x: (int(x.get("severity", 0)), -int(x.get("line", 0))),
        reverse=True
    )
    top = ordered[:k]
    out: Set[str] = set()
    for f in top:
        out |= finding_categories(f)
    return out


# ---------------- Ground Truth ----------------
def load_smartbugs_annotations(vuln_json: Path) -> Dict[str, Set[str]]:
    data = json.loads(vuln_json.read_text(errors="ignore"))
    gt: Dict[str, Set[str]] = defaultdict(set)
    for item in data:
        name = Path(item.get("name", "")).stem
        for v in item.get("vulnerabilities", []) or []:
            cat = v.get("category")
            if name and cat:
                gt[name].add(cat)
    return gt


def build_output_index(output_dir: Path) -> Dict[str, Path]:
    idx: Dict[str, Path] = {}
    for p in output_dir.glob("*.json"):
        stem = p.stem
        idx[stem] = p
        idx[strip_category_prefix(stem)] = p
    return idx


def pick_primary_gt_category(gt_cats: Set[str], fallback_stem: str) -> Optional[str]:
    """
    SmartBugs tables often use one primary label per contract.
    Prefer filename prefix (if present), else if GT has exactly 1 category.
    """
    cat = infer_category_from_filename(fallback_stem)
    if cat:
        return cat
    only = [c for c in gt_cats if c in SMARTBUGS_CATEGORIES]
    if len(only) == 1:
        return only[0]
    return None


# ---------------- Metrics ----------------
@dataclass
class PRF:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0


def accumulate_micro_prf(
    gt_labels: Set[str],
    pred_labels: Set[str],
    prf: PRF
) -> PRF:
    tp = len(gt_labels & pred_labels)
    fp = len(pred_labels - gt_labels)
    fn = len(gt_labels - pred_labels)
    return PRF(prf.tp + tp, prf.fp + fp, prf.fn + fn)


def compute_metrics_from_outputs(
    gt: Dict[str, Set[str]],
    output_dir: Path,
    supported_set: Optional[Set[str]] = None,
) -> Tuple[int, int, PRF, Dict[int, PRF]]:
    """
    Returns:
      contracts_scored, contracts_missing_output,
      micro PRF (all labels or supported-only),
      PRF@K dict for K_LIST
    """
    out_index = build_output_index(output_dir)

    contracts_scored = 0
    missing_output = 0

    micro = PRF(0, 0, 0)
    prf_at_k = {k: PRF(0, 0, 0) for k in K_LIST}

    for gt_stem, gt_cats in gt.items():
        out_file = out_index.get(gt_stem)
        if out_file is None:
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                cand = f"{cat}_{gt_stem}"
                if cand in out_index:
                    out_file = out_index[cand]
                    break

        if out_file is None or not out_file.exists():
            missing_output += 1
            continue

        try:
            payload = json.loads(out_file.read_text(errors="ignore"))
            findings = payload.get("findings", [])
        except Exception:
            missing_output += 1
            continue

        gt_labels = {c for c in gt_cats if c in SMARTBUGS_CATEGORIES}
        pred_labels = set(payload.get("detected_categories", []))

        if supported_set is not None:
            gt_labels = gt_labels & supported_set
            pred_labels = pred_labels & supported_set

        contracts_scored += 1
        micro = accumulate_micro_prf(gt_labels, pred_labels, micro)

        for k in K_LIST:
            pred_k = contract_detected_categories_topk(findings, k)
            if supported_set is not None:
                pred_k = pred_k & supported_set
            prf_at_k[k] = accumulate_micro_prf(gt_labels, pred_k, prf_at_k[k])

    return contracts_scored, missing_output, micro, prf_at_k


# ---------------- Primary-label per-category recall (Solhint-style table) ----------------
def compute_primary_label_recall_by_category(
    gt: Dict[str, Set[str]],
    output_dir: Path,
) -> Tuple[dict, Dict[str, dict]]:
    """
    Computes category-level recall using SmartBugs PRIMARY label per contract.
    Returns:
      summary: {total_scored, missing_output}
      by_cat:  cat -> {total, correct, missed, error, recall}
    """
    out_index = build_output_index(output_dir)
    by_cat = defaultdict(lambda: {"total": 0, "correct": 0, "missed": 0, "error": 0})
    total_scored = 0
    missing_output = 0

    for gt_stem, gt_cats in gt.items():
        primary_cat = pick_primary_gt_category(gt_cats, gt_stem)
        if primary_cat is None:
            continue

        out_file = out_index.get(gt_stem)
        if out_file is None:
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                cand = f"{cat}_{gt_stem}"
                if cand in out_index:
                    out_file = out_index[cand]
                    break

        total_scored += 1
        by_cat[primary_cat]["total"] += 1

        if out_file is None or not out_file.exists():
            missing_output += 1
            by_cat[primary_cat]["error"] += 1
            continue

        try:
            payload = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            missing_output += 1
            by_cat[primary_cat]["error"] += 1
            continue

        detected = set(payload.get("detected_categories", []) or [])
        if primary_cat in detected:
            by_cat[primary_cat]["correct"] += 1
        else:
            by_cat[primary_cat]["missed"] += 1

    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        denom = s["correct"] + s["missed"]
        s["recall"] = (s["correct"] / denom) if denom else 0.0

    summary = {"total_scored": total_scored, "missing_output": missing_output}
    return summary, by_cat


def write_primary_recall_csv(output_dir: Path, tool_name: str, by_cat: Dict[str, dict]) -> Path:
    out_path = output_dir / "evaluation_primary_recall_by_category.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "category", "total", "correct", "missed", "error", "recall"])
        for cat in SMARTBUGS_CATEGORIES:
            s = by_cat[cat]
            w.writerow([tool_name, cat, s["total"], s["correct"], s["missed"], s["error"], f"{s['recall']:.4f}"])
    return out_path


def write_primary_recall_latex(output_dir: Path, tool_name: str, by_cat: Dict[str, dict]) -> Path:
    out_path = output_dir / "table_primary_recall.tex"

    def esc(c: str) -> str:
        return c.replace("_", r"\_")

    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\small")
    lines.append(rf"\caption{{{tool_name.capitalize()} category-level recall (SmartBugs primary label per contract).}}")
    lines.append(rf"\label{{tab:{tool_name}-recall}}".replace("{tool_name}", tool_name))
    lines.append(r"\begin{tabular}{l r r r r}")
    lines.append(r"\hline")
    lines.append(r"\textbf{Category} & \textbf{Total} & \textbf{Correct} & \textbf{Missed} & \textbf{Recall} \\")
    lines.append(r"\hline")
    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        lines.append(f"{esc(cat)} & {s['total']} & {s['correct']} & {s['missed']} & {s['recall']:.2f} \\\\")
    lines.append(r"\hline")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


# ---------------- Main ----------------
def main():
    repo_root = Path(__file__).resolve().parent.parent  # tools/ -> repo root

    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts-dir", default=str((repo_root / "dataset/smartbugs_curated").resolve()))
    ap.add_argument("--output-dir", default=str((repo_root / "results/smartcheck").resolve()))
    ap.add_argument("--smartcheck-cmd", default="npx smartcheck")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--gt", default="", help="Path to vulnerabilities.json (auto-detect if empty)")
    ap.add_argument("--write-latex", action="store_true", help="Also write table_primary_recall.tex")
    args = ap.parse_args()

    contracts_dir = Path(args.contracts_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    if not contracts_dir.exists():
        raise FileNotFoundError(f"Contracts directory not found: {contracts_dir}")

    ensure_dir(output_dir)
    failed_log = output_dir / "failed_contracts.txt"

    gt_candidates = [
        repo_root / "dataset/smartbugs_curated/vulnerabilities.json",
        repo_root / "dataset/smartbugs-curated/vulnerabilities.json",
    ]
    gt_path = Path(args.gt).resolve() if args.gt else next((p for p in gt_candidates if p.exists()), Path(""))

    contracts = sorted(contracts_dir.rglob("*.sol"))
    print(f"Found {len(contracts)} .sol files under {contracts_dir}")

    # Failure taxonomy
    crash = 0
    empty = 0
    success = 0

    total_findings = total_err = total_warn = 0

    for i, c in enumerate(contracts, 1):
        stem = c.stem
        rel = c.relative_to(contracts_dir)
        print(f"[{i}/{len(contracts)}] {rel}")

        rc, out, err = run_smartcheck(
            c,
            smartcheck_cmd=args.smartcheck_cmd,
            timeout_s=args.timeout,
        )

        # Always write raw output
        raw_path = output_dir / f"{stem}.raw.txt"
        raw_path.write_text(
            f"RETURN_CODE:\n{rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n",
            encoding="utf-8",
            errors="ignore",
        )

        findings = parse_smartcheck_output(out)

        # crash: nonzero AND no parseable findings
        if rc != 0 and len(findings) == 0:
            crash += 1
            with open(failed_log, "a", encoding="utf-8") as f:
                f.write(f"{stem}: smartcheck crash/no parseable findings (rc={rc})\n")
            continue

        # empty: ran (rc==0 OR findings exist), but no findings parsed
        if len(findings) == 0:
            empty += 1
        else:
            success += 1

        det_cats = sorted(contract_detected_categories(findings))

        payload = {
            "tool": "smartcheck",
            "contract": str(rel),
            "contract_stem": stem,
            "returncode": rc,
            "findings": findings,
            "detected_categories": det_cats,
        }
        (output_dir / f"{stem}.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        n, e, w = smartcheck_counts(findings)
        total_findings += n
        total_err += e
        total_warn += w

        print(f"  findings: {n} errors(sev>=2): {e} warnings(sev==1): {w}")

    print("\n=== SmartCheck Run Summary ===")
    print(f"Success: {success}")
    print(f"Empty:   {empty}")
    print(f"Crash:   {crash}")
    print(f"Outputs: {output_dir}")

    if (success + empty) > 0:
        denom = (success + empty)
        print("\n=== SmartCheck Findings Summary ===")
        print(f"Total findings: {total_findings}")
        print(f"Total errors:   {total_err}")
        print(f"Total warnings: {total_warn}")
        print(f"Avg findings/contract: {total_findings / denom:.2f}")
        print(f"Avg errors/contract:   {total_err / denom:.2f}")
        print(f"Avg warnings/contract: {total_warn / denom:.2f}")

    if not args.evaluate:
        return

    if not gt_path or not gt_path.exists():
        raise FileNotFoundError(
            "Ground truth vulnerabilities.json not found. "
            "Pass --gt /path/to/vulnerabilities.json or place it under dataset/smartbugs_curated/."
        )

    gt = load_smartbugs_annotations(gt_path)

    # Overall micro + @K
    scored, missing, micro, prf_at_k = compute_metrics_from_outputs(
        gt, output_dir, supported_set=None
    )

    # Coverage-aware micro + @K
    scored_s, missing_s, micro_s, prf_at_k_s = compute_metrics_from_outputs(
        gt, output_dir, supported_set=SUPPORTED_CATEGORIES
    )

    print("\n=== SmartCheck Evaluation (Category Labels) ===")
    print(f"Contracts scored: {scored}")
    print(f"Contracts missing output: {missing}")
    print(f"Micro-TP:{micro.tp} FP:{micro.fp} FN:{micro.fn}  P:{micro.precision:.2f} R:{micro.recall:.2f} F1:{micro.f1:.2f}")
    for k in K_LIST:
        m = prf_at_k[k]
        print(f"P@{k}:{m.precision:.2f} R@{k}:{m.recall:.2f} F1@{k}:{m.f1:.2f}")

    print("\n=== SmartCheck Coverage-Aware (Supported Only) ===")
    print(f"Supported categories: {sorted(SUPPORTED_CATEGORIES)}")
    print(f"Contracts scored: {scored_s}")
    print(f"Contracts missing output: {missing_s}")
    print(f"Micro-TP:{micro_s.tp} FP:{micro_s.fp} FN:{micro_s.fn}  P:{micro_s.precision:.2f} R:{micro_s.recall:.2f} F1:{micro_s.f1:.2f}")
    for k in K_LIST:
        m = prf_at_k_s[k]
        print(f"Supported P@{k}:{m.precision:.2f} R@{k}:{m.recall:.2f} F1@{k}:{m.f1:.2f}")

    # ---- NEW: Primary-label category-level recall table (Solhint-style) ----
    primary_summary, primary_by_cat = compute_primary_label_recall_by_category(gt, output_dir)

    print("\n=== SmartCheck Category-Level Recall (Primary Label per Contract) ===")
    print(f"Total contracts (primary-labeled) scored: {primary_summary['total_scored']}")
    print(f"Missing output (primary-labeled): {primary_summary['missing_output']}")
    for cat in SMARTBUGS_CATEGORIES:
        s = primary_by_cat[cat]
        print(f"{cat} Total:{s['total']} Correct:{s['correct']} Missed:{s['missed']} Error:{s['error']} Recall:{s['recall']:.2f}")

    out_primary_csv = write_primary_recall_csv(output_dir, "smartcheck", primary_by_cat)
    print(f"Wrote: {out_primary_csv}")

    if args.write_latex:
        out_tex = write_primary_recall_latex(output_dir, "smartcheck", primary_by_cat)
        print(f"Wrote: {out_tex}")

    # Write common CSV schema
    out_csv = output_dir / "evaluation_common.csv"
    headers = [
        "tool",
        "contracts_total",
        "contracts_success",
        "contracts_crash",
        "contracts_empty",
        "contracts_scored",
        "contracts_missing_output",
        "supported_categories",
        "micro_tp", "micro_fp", "micro_fn", "micro_precision", "micro_recall", "micro_f1",
        "supported_tp", "supported_fp", "supported_fn", "supported_precision", "supported_recall", "supported_f1",
        # Primary-label summary columns (optional but handy for consistency with Solhint-style tables)
        "primary_total_scored",
        "primary_missing_output",
    ]
    for k in K_LIST:
        headers += [f"p_at_{k}", f"r_at_{k}", f"f1_at_{k}"]
    for k in K_LIST:
        headers += [f"supported_p_at_{k}", f"supported_r_at_{k}", f"supported_f1_at_{k}"]

    row = {
        "tool": "smartcheck",
        "contracts_total": len(contracts),
        "contracts_success": success,
        "contracts_crash": crash,
        "contracts_empty": empty,
        "contracts_scored": scored,
        "contracts_missing_output": missing,
        "supported_categories": "|".join(sorted(SUPPORTED_CATEGORIES)),
        "micro_tp": micro.tp,
        "micro_fp": micro.fp,
        "micro_fn": micro.fn,
        "micro_precision": f"{micro.precision:.6f}",
        "micro_recall": f"{micro.recall:.6f}",
        "micro_f1": f"{micro.f1:.6f}",
        "supported_tp": micro_s.tp,
        "supported_fp": micro_s.fp,
        "supported_fn": micro_s.fn,
        "supported_precision": f"{micro_s.precision:.6f}",
        "supported_recall": f"{micro_s.recall:.6f}",
        "supported_f1": f"{micro_s.f1:.6f}",
        "primary_total_scored": primary_summary["total_scored"],
        "primary_missing_output": primary_summary["missing_output"],
    }
    for k in K_LIST:
        m = prf_at_k[k]
        row[f"p_at_{k}"] = f"{m.precision:.6f}"
        row[f"r_at_{k}"] = f"{m.recall:.6f}"
        row[f"f1_at_{k}"] = f"{m.f1:.6f}"
    for k in K_LIST:
        m = prf_at_k_s[k]
        row[f"supported_p_at_{k}"] = f"{m.precision:.6f}"
        row[f"supported_r_at_{k}"] = f"{m.recall:.6f}"
        row[f"supported_f1_at_{k}"] = f"{m.f1:.6f}"

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerow(row)

    print(f"\nWrote: {out_csv}")


if __name__ == "__main__":
    main()
