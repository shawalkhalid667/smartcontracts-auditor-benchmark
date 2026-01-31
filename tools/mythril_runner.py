#!/usr/bin/env python3
"""
mythril_runner.py

Runs Mythril on SmartBugs-Curated-like dataset and evaluates against vulnerabilities.json,
using the SAME tool-agnostic metrics schema as smartcheck_runner.py.

Key fix vs "all failing non-JSON":
- Mythril often prints non-JSON logs/banners; we extract JSON object from stdout/stderr.

Outputs per contract:
- results/mythril/<stem>.raw.txt        (always)
- results/mythril/<stem>.json           (clean Mythril JSON only; only if parsed)
- results/mythril/<stem>.meta.json      (tool-agnostic metadata; only if parsed)

Evaluation (--evaluate):
- results/mythril/evaluation_common.csv (common schema)
- results/mythril/evaluation_primary_by_category.csv (primary-label recall table)
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


# ---------------- Paths ----------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

CONTRACT_DIR_DEFAULT = (REPO_ROOT / "dataset/smartbugs_curated").resolve()
VERSIONS_DIR_DEFAULT = (REPO_ROOT / "dataset/versions").resolve()
OUTPUT_DIR_DEFAULT = (REPO_ROOT / "results/mythril").resolve()

GT_CANDIDATES = [
    REPO_ROOT / "dataset/smartbugs_curated/vulnerabilities.json",
    REPO_ROOT / "dataset/smartbugs-curated/vulnerabilities.json",
]


# ---------------- Mythril Category Mapping ----------------
# NOTE: these are CATEGORY labels, not SWC labels.
# Keep "supported categories" as the set of labels Mythril can reasonably emit here.
SUPPORTED_CATEGORIES: Set[str] = {
    "reentrancy",
    "access_control",
    "arithmetic",
    "bad_randomness",
    "denial_of_service",
    "front_running",
    "time_manipulation",
    "unchecked_low_level_calls",
    "short_addresses",
}


# ---------------- Utilities ----------------
def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_unlink(p: Path) -> None:
    try:
        p.unlink()
    except FileNotFoundError:
        return
    except Exception:
        return


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


def extract_version_from_pragma(pragma_str: str) -> Optional[str]:
    if not pragma_str:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", pragma_str)
    return m.group(1) if m else None


def read_contract_version(versions_dir: Path, stem: str) -> Tuple[Optional[str], Optional[str]]:
    vf = versions_dir / f"{stem}.json"
    if not vf.exists():
        return None, None
    try:
        data = json.loads(vf.read_text(errors="ignore"))
        pragma = data.get("pragma", "")
        return extract_version_from_pragma(pragma), pragma
    except Exception:
        return None, None


def solc_select_install_and_use(version: str) -> bool:
    # install quietly (ok if already installed)
    subprocess.run(
        ["solc-select", "install", version],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    # switch
    try:
        subprocess.run(
            ["solc-select", "use", version],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def run_mythril(contract_path: Path) -> Tuple[int, str, str]:
    """
    Returns (returncode, stdout, stderr). No timeouts.
    """
    cmd = ["myth", "analyze", str(contract_path), "-o", "json"]
    r = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return r.returncode, r.stdout.decode(errors="ignore"), r.stderr.decode(errors="ignore")


def extract_first_json_object(text: str) -> Optional[str]:
    """
    Mythril sometimes prints logs before/after JSON.
    Extract the first top-level JSON object by finding first '{' and last '}'.

    This is intentionally simple and robust for Mythril's output.
    """
    if not text:
        return None
    i = text.find("{")
    j = text.rfind("}")
    if i == -1 or j == -1 or j < i:
        return None
    candidate = text[i:j+1]
    try:
        obj = json.loads(candidate)
        if isinstance(obj, dict):
            return candidate
    except Exception:
        return None
    return None


# ---------------- Ground Truth ----------------
def load_smartbugs_annotations(vuln_json: Path) -> Dict[str, Set[str]]:
    """
    Returns contract_stem -> set(categories)
    Supports SmartBugs curated schema with {"name":..., "vulnerabilities":[{"category":...},...]}
    and older variants that may use {"file":..., "category":...}.
    """
    data = json.loads(vuln_json.read_text(errors="ignore"))
    gt: Dict[str, Set[str]] = defaultdict(set)

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue

            # Schema A
            if "name" in item and "vulnerabilities" in item:
                stem = Path(item.get("name", "")).stem
                vulns = item.get("vulnerabilities") or []
                if stem and isinstance(vulns, list):
                    for v in vulns:
                        if isinstance(v, dict):
                            cat = v.get("category")
                            if cat:
                                gt[stem].add(cat)

            # Schema B
            elif "file" in item:
                stem = Path(item.get("file", "")).stem
                if stem:
                    cat = item.get("category")
                    if cat:
                        gt[stem].add(cat)
                    cats = item.get("categories")
                    if isinstance(cats, list):
                        for c in cats:
                            if c:
                                gt[stem].add(c)

    return gt


def build_output_index(output_dir: Path) -> Dict[str, Path]:
    """
    Index clean JSON outputs by multiple keys to handle prefix/stem mismatches.
    We index:
      - exact stem
      - stripped category prefix stem (access_control_Foo -> Foo)
    """
    idx: Dict[str, Path] = {}
    for p in output_dir.glob("*.json"):
        # skip meta json
        if p.name.endswith(".meta.json"):
            continue
        stem = p.stem
        idx[stem] = p
        idx[strip_category_prefix(stem)] = p
    return idx


# ---------------- Mythril Output Parsing ----------------
def issue_severity_rank(issue: dict) -> int:
    """
    Mythril uses 'severity' as string e.g., 'High', 'Medium', 'Low'.
    Higher rank => earlier in Top-K.
    """
    sev = (issue.get("severity") or "").strip().lower()
    if sev == "high":
        return 3
    if sev == "medium":
        return 2
    if sev == "low":
        return 1
    return 0


def map_issue_to_categories(issue: dict) -> Set[str]:
    """
    Map Mythril issue (title, swc-id) to SmartBugs category labels.
    """
    title = (issue.get("title", "") or "").lower()
    swc = (issue.get("swc-id", "") or "").strip()

    cats: Set[str] = set()

    # Reentrancy
    if swc == "107" or "reentrancy" in title:
        cats.add("reentrancy")

    # Access control / auth
    if swc in {"105", "106", "115"} or any(k in title for k in ["access control", "authorization", "owner", "authentication"]):
        cats.add("access_control")

    # Arithmetic
    if swc in {"101", "102", "120", "123"} or any(k in title for k in ["overflow", "underflow", "integer"]):
        cats.add("arithmetic")

    # Randomness
    if swc in {"120"} or "random" in title or "blockhash" in title:
        cats.add("bad_randomness")

    # DoS
    if "dos" in title or "denial" in title:
        cats.add("denial_of_service")

    # Front-running / TOD
    if any(k in title for k in ["front", "transaction order", "tod"]):
        cats.add("front_running")

    # Time manipulation / timestamp
    if swc in {"116"} or any(k in title for k in ["timestamp", "time manipulation", "block.timestamp", "now "]):
        cats.add("time_manipulation")

    # Unchecked low-level calls
    if swc in {"104"} or ("unchecked" in title and "call" in title) or "low level call" in title:
        cats.add("unchecked_low_level_calls")

    # Short address
    if "short address" in title:
        cats.add("short_addresses")

    return cats


def extract_detected_categories_from_mythril_json(mythril_obj: dict) -> Set[str]:
    cats: Set[str] = set()
    for issue in (mythril_obj.get("issues") or []):
        if isinstance(issue, dict):
            cats |= map_issue_to_categories(issue)
    return cats


def extract_detected_categories_topk(mythril_obj: dict, k: int) -> Set[str]:
    issues = [i for i in (mythril_obj.get("issues") or []) if isinstance(i, dict)]
    # Sort by severity desc, then by presence of swc-id/title (stable-ish)
    issues_sorted = sorted(
        issues,
        key=lambda x: (issue_severity_rank(x), 1 if x.get("swc-id") else 0),
        reverse=True,
    )
    top = issues_sorted[:k]
    cats: Set[str] = set()
    for issue in top:
        cats |= map_issue_to_categories(issue)
    return cats


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


def accumulate_micro_prf(gt_labels: Set[str], pred_labels: Set[str], prf: PRF) -> PRF:
    tp = len(gt_labels & pred_labels)
    fp = len(pred_labels - gt_labels)
    fn = len(gt_labels - pred_labels)
    return PRF(prf.tp + tp, prf.fp + fp, prf.fn + fn)


def compute_micro_and_topk(
    gt: Dict[str, Set[str]],
    output_dir: Path,
    supported_set: Optional[Set[str]] = None,
) -> Tuple[int, int, PRF, Dict[int, PRF]]:
    """
    Returns:
      contracts_scored, contracts_missing_output,
      micro PRF,
      PRF@K for K_LIST
    """
    out_index = build_output_index(output_dir)

    scored = 0
    missing = 0
    micro = PRF(0, 0, 0)
    prf_at_k = {k: PRF(0, 0, 0) for k in K_LIST}

    for gt_stem, gt_cats in gt.items():
        out_file = out_index.get(gt_stem)
        if out_file is None:
            # try prefixed name: <cat>_<gt_stem>
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                cand = f"{cat}_{gt_stem}"
                if cand in out_index:
                    out_file = out_index[cand]
                    break

        if out_file is None or not out_file.exists():
            missing += 1
            continue

        try:
            myth = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            missing += 1
            continue

        gt_labels = {c for c in gt_cats if c in SMARTBUGS_CATEGORIES}
        pred_labels = extract_detected_categories_from_mythril_json(myth)

        if supported_set is not None:
            gt_labels = gt_labels & supported_set
            pred_labels = pred_labels & supported_set

        scored += 1
        micro = accumulate_micro_prf(gt_labels, pred_labels, micro)

        for k in K_LIST:
            pred_k = extract_detected_categories_topk(myth, k)
            if supported_set is not None:
                pred_k = pred_k & supported_set
            prf_at_k[k] = accumulate_micro_prf(gt_labels, pred_k, prf_at_k[k])

    return scored, missing, micro, prf_at_k


def compute_primary_label_recall_table(
    gt: Dict[str, Set[str]],
    output_dir: Path,
) -> Dict[str, dict]:
    """
    Primary label per contract = inferred from filename prefix if available;
    otherwise if GT has exactly one known category.

    Returns per-category:
      total, correct, missed, error, recall
    """
    out_index = build_output_index(output_dir)
    by_cat = defaultdict(lambda: {"total": 0, "correct": 0, "missed": 0, "error": 0})

    for gt_stem, gt_cats in gt.items():
        primary = infer_category_from_filename(gt_stem)
        if primary is None:
            only = [c for c in gt_cats if c in SMARTBUGS_CATEGORIES]
            if len(only) == 1:
                primary = only[0]
        if primary is None:
            continue

        by_cat[primary]["total"] += 1

        out_file = out_index.get(gt_stem)
        if out_file is None:
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                cand = f"{cat}_{gt_stem}"
                if cand in out_index:
                    out_file = out_index[cand]
                    break

        if out_file is None or not out_file.exists():
            by_cat[primary]["error"] += 1
            continue

        try:
            myth = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            by_cat[primary]["error"] += 1
            continue

        detected = extract_detected_categories_from_mythril_json(myth)

        if primary in detected:
            by_cat[primary]["correct"] += 1
        else:
            by_cat[primary]["missed"] += 1

    # add recall field
    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        denom = (s["correct"] + s["missed"])
        s["recall"] = (s["correct"] / denom) if denom else 0.0

    return by_cat


# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts-dir", default=str(CONTRACT_DIR_DEFAULT))
    ap.add_argument("--versions-dir", default=str(VERSIONS_DIR_DEFAULT))
    ap.add_argument("--output-dir", default=str(OUTPUT_DIR_DEFAULT))
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--clean", action="store_true", help="Remove previous mythril outputs (safe)")
    ap.add_argument("--gt", default="", help="Path to vulnerabilities.json (auto-detect if empty)")
    args = ap.parse_args()

    contracts_dir = Path(args.contracts_dir).resolve()
    versions_dir = Path(args.versions_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    ensure_dir(output_dir)

    if args.clean:
        for p in output_dir.glob("*"):
            if p.is_file():
                safe_unlink(p)

    contracts = sorted(contracts_dir.rglob("*.sol"))
    print(f"Found {len(contracts)} .sol files under {contracts_dir}")

    # Failure taxonomy
    success = 0
    empty = 0
    crash = 0
    missing_version = 0
    solc_fail = 0

    for i, c in enumerate(contracts, 1):
        stem = c.stem
        rel = c.relative_to(contracts_dir)
        version, pragma = read_contract_version(versions_dir, stem)

        print(f"\n[{i}/{len(contracts)}] Evaluating {rel}...")

        if not version:
            print("[!] Missing version")
            missing_version += 1
            crash += 1
            continue

        if not solc_select_install_and_use(version):
            print("[!] solc-select failed")
            solc_fail += 1
            crash += 1
            continue

        rc, out, err = run_mythril(c)

        # Always write raw output
        raw_path = output_dir / f"{stem}.raw.txt"
        raw_path.write_text(
            f"RETURN_CODE:\n{rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n",
            encoding="utf-8",
            errors="ignore",
        )

        # Extract JSON from stdout, then stderr as fallback
        json_text = extract_first_json_object(out)
        if json_text is None:
            json_text = extract_first_json_object(err)

        if json_text is None:
            print("[!] Mythril failed / non-JSON")
            crash += 1
            # keep a short error file for quick grep
            (output_dir / f"{stem}.error.txt").write_text(
                (err or out)[:20000],
                encoding="utf-8",
                errors="ignore",
            )
            continue

        try:
            myth_obj = json.loads(json_text)
            if not isinstance(myth_obj, dict):
                raise ValueError("Mythril JSON is not an object")
        except Exception:
            print("[!] Mythril failed / JSON parse error after extraction")
            crash += 1
            (output_dir / f"{stem}.error.txt").write_text(
                (err or out)[:20000],
                encoding="utf-8",
                errors="ignore",
            )
            continue

        # Determine empty vs success
        issues = myth_obj.get("issues") or []
        if isinstance(issues, list) and len(issues) == 0:
            empty += 1
        else:
            success += 1

        # Write clean JSON only (for evaluation)
        (output_dir / f"{stem}.json").write_text(
            json.dumps(myth_obj, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        detected = sorted(extract_detected_categories_from_mythril_json(myth_obj))

        meta = {
            "tool": "mythril",
            "contract": str(rel),
            "contract_stem": stem,
            "pragma": pragma,
            "solc_version": version,
            "returncode": rc,
            "detected_categories": detected,
            # keep a light “rankable” view of issues for debugging
            "issues_ranked": sorted(
                [
                    {
                        "swc-id": (iss.get("swc-id") if isinstance(iss, dict) else None),
                        "title": (iss.get("title") if isinstance(iss, dict) else None),
                        "severity": (iss.get("severity") if isinstance(iss, dict) else None),
                    }
                    for iss in issues
                    if isinstance(iss, dict)
                ],
                key=lambda x: ({"high": 3, "medium": 2, "low": 1}.get((x.get("severity") or "").lower(), 0)),
                reverse=True,
            ),
        }
        (output_dir / f"{stem}.meta.json").write_text(
            json.dumps(meta, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        print("[✓] Mythril parsed JSON")

    print("\n=== Mythril Run Summary ===")
    print(f"Success: {success}")
    print(f"Empty:   {empty}")
    print(f"Crash:   {crash}")
    print(f"Missing version: {missing_version}")
    print(f"solc-select failures: {solc_fail}")
    print(f"Outputs: {output_dir}")

    if not args.evaluate:
        return

    gt_path = Path(args.gt).resolve() if args.gt else next((p for p in GT_CANDIDATES if p.exists()), Path(""))
    if not gt_path or not gt_path.exists():
        raise FileNotFoundError(
            "Ground truth vulnerabilities.json not found. "
            "Pass --gt /path/to/vulnerabilities.json or place it under dataset/smartbugs_curated/."
        )

    gt = load_smartbugs_annotations(gt_path)

    # Overall micro + @K
    scored, missing_out, micro, prf_at_k = compute_micro_and_topk(
        gt, output_dir, supported_set=None
    )

    # Coverage-aware micro + @K
    scored_s, missing_out_s, micro_s, prf_at_k_s = compute_micro_and_topk(
        gt, output_dir, supported_set=SUPPORTED_CATEGORIES
    )

    # Primary-label per-category recall
    by_cat = compute_primary_label_recall_table(gt, output_dir)

    print("\n=== Mythril Evaluation (Category Labels) ===")
    print(f"Contracts scored: {scored}")
    print(f"Contracts missing output: {missing_out}")
    print(f"Micro-TP:{micro.tp} FP:{micro.fp} FN:{micro.fn}  P:{micro.precision:.2f} R:{micro.recall:.2f} F1:{micro.f1:.2f}")
    for k in K_LIST:
        m = prf_at_k[k]
        print(f"P@{k}:{m.precision:.2f} R@{k}:{m.recall:.2f} F1@{k}:{m.f1:.2f}")

    print("\n=== Mythril Coverage-Aware (Supported Only) ===")
    print(f"Supported categories: {sorted(SUPPORTED_CATEGORIES)}")
    print(f"Contracts scored: {scored_s}")
    print(f"Contracts missing output: {missing_out_s}")
    print(f"Micro-TP:{micro_s.tp} FP:{micro_s.fp} FN:{micro_s.fn}  P:{micro_s.precision:.2f} R:{micro_s.recall:.2f} F1:{micro_s.f1:.2f}")
    for k in K_LIST:
        m = prf_at_k_s[k]
        print(f"Supported P@{k}:{m.precision:.2f} R@{k}:{m.recall:.2f} F1@{k}:{m.f1:.2f}")

    print("\n=== Mythril Per-Category Recall (Primary Label) ===")
    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        print(f"{cat} Total:{s['total']} Correct:{s['correct']} Missed:{s['missed']} Error:{s['error']} Recall:{s['recall']:.2f}")

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
        "primary_total_scored",
        "primary_missing_output",
    ]
    for k in K_LIST:
        headers += [f"p_at_{k}", f"r_at_{k}", f"f1_at_{k}"]
    for k in K_LIST:
        headers += [f"supported_p_at_{k}", f"supported_r_at_{k}", f"supported_f1_at_{k}"]

    # For primary_* fields: in your pipeline you treat primary_total_scored as "how many GT entries we used"
    # We'll count those where primary label is defined (i.e., included in by_cat totals).
    primary_total_scored = sum(by_cat[c]["total"] for c in SMARTBUGS_CATEGORIES)
    primary_missing_output = sum(by_cat[c]["error"] for c in SMARTBUGS_CATEGORIES)

    row = {
        "tool": "mythril",
        "contracts_total": len(contracts),
        "contracts_success": success,
        "contracts_crash": crash,
        "contracts_empty": empty,
        "contracts_scored": scored,
        "contracts_missing_output": missing_out,
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
        "primary_total_scored": primary_total_scored,
        "primary_missing_output": primary_missing_output,
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

    # Write primary label by category (paper table)
    out_primary = output_dir / "evaluation_primary_by_category.csv"
    with open(out_primary, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "category", "total", "correct", "missed", "error", "recall"])
        for cat in SMARTBUGS_CATEGORIES:
            s = by_cat[cat]
            w.writerow(["mythril", cat, s["total"], s["correct"], s["missed"], s["error"], f"{s['recall']:.6f}"])

    print(f"\nWrote: {out_csv}")
    print(f"Wrote: {out_primary}")


if __name__ == "__main__":
    main()
