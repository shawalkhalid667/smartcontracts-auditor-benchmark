#!/usr/bin/env python3
"""
slither_runner.py

Runs Slither on SmartBugs-Curated-like dataset and evaluates against vulnerabilities.json,
using the SAME tool-agnostic metrics schema as smartcheck_runner.py / mythril_runner.py.

Outputs per contract:
- results/slither/<stem>.raw.txt        (always)
- results/slither/<stem>.json           (clean Slither JSON only; only if parsed)
- results/slither/<stem>.meta.json      (tool-agnostic metadata; only if parsed)

Evaluation (--evaluate):
- results/slither/evaluation_common.csv (common schema)
- results/slither/evaluation_primary_by_category.csv (primary-label recall table)

Notes:
- Slither relies on solc; this runner uses dataset/versions/<stem>.json + solc-select
  (same convention as mythril_runner.py) to minimize version-related failures.
- Mapping from Slither detectors -> SmartBugs categories is heuristic; keep it conservative,
  then expand after inspecting your slither JSON outputs.
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
OUTPUT_DIR_DEFAULT = (REPO_ROOT / "results/slither").resolve()

GT_CANDIDATES = [
    REPO_ROOT / "dataset/smartbugs_curated/vulnerabilities.json",
    REPO_ROOT / "dataset/smartbugs-curated/vulnerabilities.json",
]


# ---------------- Supported Categories ----------------
# Slither can emit many security findings; we keep supported categories aligned to your SmartBugs labels.
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
    # "other" is intentionally not counted as supported for "coverage-aware" unless you want it.
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
    """
    Reads dataset/versions/<stem>.json created by your dataset preprocessing.
    Expected fields: {"pragma": "..."} (same assumption as mythril_runner.py).
    Returns (version, pragma_str).
    """
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


def extract_first_json_object(text: str) -> Optional[str]:
    """
    Slither sometimes prints logs; extract the first top-level JSON object by finding first '{' and last '}'.
    Same robust approach used in mythril_runner.py.
    """
    if not text:
        return None
    i = text.find("{")
    j = text.rfind("}")
    if i == -1 or j == -1 or j < i:
        return None
    candidate = text[i : j + 1]
    try:
        obj = json.loads(candidate)
        if isinstance(obj, dict):
            return candidate
    except Exception:
        return None
    return None


def run_slither(contract_path: Path, slither_cmd: str, timeout_s: Optional[int]) -> Tuple[int, str, str]:
    """
    Preferred: slither <contract>.sol --json -
    The '-' tells Slither to print JSON to stdout (supported in recent Slither versions).
    """
    base = slither_cmd.split()
    cmd = base + [str(contract_path), "--json", "-"]
    r = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_s,
    )
    return r.returncode, r.stdout.decode(errors="ignore"), r.stderr.decode(errors="ignore")


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


# ---------------- Slither Output Parsing ----------------
# Slither JSON schema (typical):
# {
#   "success": true,
#   "results": {
#     "detectors": [
#        {"check":"reentrancy-eth", "impact":"High", "confidence":"High", "description":"...", ...},
#        ...
#     ],
#     ...
#   }
# }
#
# We map detectors -> SmartBugs categories using conservative keyword rules.
#
# Tip: print a few detector["check"] values from your outputs and expand these rules.
def detector_text(det: dict) -> str:
    chk = (det.get("check") or "")
    desc = (det.get("description") or "")
    return f"{chk}\n{desc}".lower()


def map_detector_to_categories(det: dict) -> Set[str]:
    t = detector_text(det)
    cats: Set[str] = set()

    # Reentrancy
    if "reentrancy" in t:
        cats.add("reentrancy")

    # Unchecked low-level calls / return values
    if any(k in t for k in ["unchecked low level", "unchecked-lowlevel", "unchecked send", "unchecked call", "unchecked external call"]):
        cats.add("unchecked_low_level_calls")
    if any(k in t for k in ["unused return", "unchecked return", "unchecked-return", "unchecked call return"]):
        cats.add("unchecked_low_level_calls")
    if any(k in t for k in ["low level call", "low-level call", "delegatecall", "callcode"]):
        # delegatecall often overlaps access control; keep conservative:
        cats.add("unchecked_low_level_calls")

    # Time manipulation / timestamp dependence
    if any(k in t for k in ["timestamp", "block.timestamp", "now ", "time manipulation", "time-dependent", "time dependent"]):
        cats.add("time_manipulation")

    # Bad randomness
    if any(k in t for k in ["weak prng", "bad randomness", "random", "blockhash", "keccak", "predictable", "predictability"]):
        # beware: keccak presence alone can be noisy; require "random"/"blockhash"/"prng"/"predictable"
        if any(k in t for k in ["random", "blockhash", "prng", "predictable"]):
            cats.add("bad_randomness")

    # Arithmetic (overflow/underflow)
    if any(k in t for k in ["overflow", "underflow", "arithmetic", "integer overflow", "integer underflow", "wraparound"]):
        cats.add("arithmetic")

    # Front-running / transaction ordering dependence
    if any(k in t for k in ["front running", "front-running", "transaction ordering", "tod", "race condition", "transaction-order"]):
        cats.add("front_running")

    # Access control / authorization / ownership / tx.origin
    if any(k in t for k in ["tx.origin", "onlyowner", "only owner", "owner", "authorization", "access control", "unprotected", "missing access control", "arbitrary from", "arbitrary write", "unrestricted"]):
        cats.add("access_control")

    # DoS patterns
    if any(k in t for k in ["denial of service", "dos", "revert in loop", "call in loop", "unbounded loop", "gas grief", "out of gas", "block gas limit"]):
        cats.add("denial_of_service")

    # Short address (rare; mostly historical)
    if "short address" in t or "short-address" in t:
        cats.add("short_addresses")

    # If nothing mapped, leave empty (don’t force "other" for coverage-aware fairness).
    return cats


def extract_detectors(slither_obj: dict) -> List[dict]:
    res = slither_obj.get("results") or {}
    dets = res.get("detectors") or []
    if isinstance(dets, list):
        return [d for d in dets if isinstance(d, dict)]
    return []


def extract_detected_categories_from_slither_json(slither_obj: dict) -> Set[str]:
    cats: Set[str] = set()
    for det in extract_detectors(slither_obj):
        cats |= map_detector_to_categories(det)
    return cats


def impact_rank(det: dict) -> int:
    """
    Slither impact is typically: High/Medium/Low/Informational/Optimization
    Higher rank => earlier in Top-K.
    """
    imp = (det.get("impact") or "").strip().lower()
    if imp == "high":
        return 4
    if imp == "medium":
        return 3
    if imp == "low":
        return 2
    if imp == "informational":
        return 1
    if imp == "optimization":
        return 0
    return 0


def confidence_rank(det: dict) -> int:
    """
    Slither confidence: High/Medium/Low (sometimes empty)
    """
    conf = (det.get("confidence") or "").strip().lower()
    if conf == "high":
        return 3
    if conf == "medium":
        return 2
    if conf == "low":
        return 1
    return 0


def extract_detected_categories_topk(slither_obj: dict, k: int) -> Set[str]:
    dets = extract_detectors(slither_obj)
    dets_sorted = sorted(
        dets,
        key=lambda d: (impact_rank(d), confidence_rank(d), 1 if d.get("check") else 0),
        reverse=True,
    )
    top = dets_sorted[:k]
    cats: Set[str] = set()
    for det in top:
        cats |= map_detector_to_categories(det)
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
    prf_at_k = {kk: PRF(0, 0, 0) for kk in K_LIST}

    for gt_stem, gt_cats in gt.items():
        out_file = out_index.get(gt_stem)
        if out_file is None:
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                cand = f"{cat}_{gt_stem}"
                if cand in out_index:
                    out_file = out_index[cand]
                    break

        if out_file is None or not out_file.exists():
            missing += 1
            continue

        try:
            sl = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            missing += 1
            continue

        gt_labels = {c for c in gt_cats if c in SMARTBUGS_CATEGORIES}
        pred_labels = extract_detected_categories_from_slither_json(sl)

        if supported_set is not None:
            gt_labels = gt_labels & supported_set
            pred_labels = pred_labels & supported_set

        scored += 1
        micro = accumulate_micro_prf(gt_labels, pred_labels, micro)

        for kk in K_LIST:
            pred_k = extract_detected_categories_topk(sl, kk)
            if supported_set is not None:
                pred_k = pred_k & supported_set
            prf_at_k[kk] = accumulate_micro_prf(gt_labels, pred_k, prf_at_k[kk])

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
            sl = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            by_cat[primary]["error"] += 1
            continue

        detected = extract_detected_categories_from_slither_json(sl)

        if primary in detected:
            by_cat[primary]["correct"] += 1
        else:
            by_cat[primary]["missed"] += 1

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
    ap.add_argument("--slither-cmd", default="slither", help='Slither command, e.g., "slither" or "python -m slither"')
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--clean", action="store_true", help="Remove previous slither outputs (safe)")
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
    timeout_fail = 0

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

        try:
            rc, out, err = run_slither(c, args.slither_cmd, args.timeout)
        except subprocess.TimeoutExpired:
            print("[!] Slither timeout")
            timeout_fail += 1
            crash += 1
            raw_path = output_dir / f"{stem}.raw.txt"
            raw_path.write_text(
                "RETURN_CODE:\nTIMEOUT\n\nSTDOUT:\n\n\nSTDERR:\nTIMEOUT\n",
                encoding="utf-8",
                errors="ignore",
            )
            (output_dir / f"{stem}.error.txt").write_text(
                "TIMEOUT",
                encoding="utf-8",
                errors="ignore",
            )
            continue

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
            print("[!] Slither failed / non-JSON")
            crash += 1
            (output_dir / f"{stem}.error.txt").write_text(
                (err or out)[:20000],
                encoding="utf-8",
                errors="ignore",
            )
            continue

        try:
            sl_obj = json.loads(json_text)
            if not isinstance(sl_obj, dict):
                raise ValueError("Slither JSON is not an object")
        except Exception:
            print("[!] Slither failed / JSON parse error after extraction")
            crash += 1
            (output_dir / f"{stem}.error.txt").write_text(
                (err or out)[:20000],
                encoding="utf-8",
                errors="ignore",
            )
            continue

        # Determine empty vs success (no detectors)
        dets = extract_detectors(sl_obj)
        if len(dets) == 0:
            empty += 1
        else:
            success += 1

        # Write clean JSON only (for evaluation)
        (output_dir / f"{stem}.json").write_text(
            json.dumps(sl_obj, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        detected = sorted(extract_detected_categories_from_slither_json(sl_obj))

        # Rank detectors for debugging / Top-K sanity
        dets_ranked = sorted(
            [
                {
                    "check": d.get("check"),
                    "impact": d.get("impact"),
                    "confidence": d.get("confidence"),
                }
                for d in dets
            ],
            key=lambda d: ({"high": 4, "medium": 3, "low": 2, "informational": 1, "optimization": 0}.get((d.get("impact") or "").lower(), 0),
                           {"high": 3, "medium": 2, "low": 1}.get((d.get("confidence") or "").lower(), 0)),
            reverse=True,
        )

        meta = {
            "tool": "slither",
            "contract": str(rel),
            "contract_stem": stem,
            "pragma": pragma,
            "solc_version": version,
            "returncode": rc,
            "detected_categories": detected,
            "detectors_ranked": dets_ranked[:100],  # keep it light
        }
        (output_dir / f"{stem}.meta.json").write_text(
            json.dumps(meta, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        print("[✓] Slither parsed JSON")

    print("\n=== Slither Run Summary ===")
    print(f"Success: {success}")
    print(f"Empty:   {empty}")
    print(f"Crash:   {crash}")
    print(f"Missing version: {missing_version}")
    print(f"solc-select failures: {solc_fail}")
    print(f"Timeouts: {timeout_fail}")
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

    print("\n=== Slither Evaluation (Category Labels) ===")
    print(f"Contracts scored: {scored}")
    print(f"Contracts missing output: {missing_out}")
    print(f"Micro-TP:{micro.tp} FP:{micro.fp} FN:{micro.fn}  P:{micro.precision:.2f} R:{micro.recall:.2f} F1:{micro.f1:.2f}")
    for kk in K_LIST:
        m = prf_at_k[kk]
        print(f"P@{kk}:{m.precision:.2f} R@{kk}:{m.recall:.2f} F1@{kk}:{m.f1:.2f}")

    print("\n=== Slither Coverage-Aware (Supported Only) ===")
    print(f"Supported categories: {sorted(SUPPORTED_CATEGORIES)}")
    print(f"Contracts scored: {scored_s}")
    print(f"Contracts missing output: {missing_out_s}")
    print(f"Micro-TP:{micro_s.tp} FP:{micro_s.fp} FN:{micro_s.fn}  P:{micro_s.precision:.2f} R:{micro_s.recall:.2f} F1:{micro_s.f1:.2f}")
    for kk in K_LIST:
        m = prf_at_k_s[kk]
        print(f"Supported P@{kk}:{m.precision:.2f} R@{kk}:{m.recall:.2f} F1@{kk}:{m.f1:.2f}")

    print("\n=== Slither Per-Category Recall (Primary Label) ===")
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
    for kk in K_LIST:
        headers += [f"p_at_{kk}", f"r_at_{kk}", f"f1_at_{kk}"]
    for kk in K_LIST:
        headers += [f"supported_p_at_{kk}", f"supported_r_at_{kk}", f"supported_f1_at_{kk}"]

    primary_total_scored = sum(by_cat[c]["total"] for c in SMARTBUGS_CATEGORIES)
    primary_missing_output = sum(by_cat[c]["error"] for c in SMARTBUGS_CATEGORIES)

    row = {
        "tool": "slither",
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
    for kk in K_LIST:
        m = prf_at_k[kk]
        row[f"p_at_{kk}"] = f"{m.precision:.6f}"
        row[f"r_at_{kk}"] = f"{m.recall:.6f}"
        row[f"f1_at_{kk}"] = f"{m.f1:.6f}"
    for kk in K_LIST:
        m = prf_at_k_s[kk]
        row[f"supported_p_at_{kk}"] = f"{m.precision:.6f}"
        row[f"supported_r_at_{kk}"] = f"{m.recall:.6f}"
        row[f"supported_f1_at_{kk}"] = f"{m.f1:.6f}"

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
            w.writerow(["slither", cat, s["total"], s["correct"], s["missed"], s["error"], f"{s['recall']:.6f}"])

    print(f"\nWrote: {out_csv}")
    print(f"Wrote: {out_primary}")


if __name__ == "__main__":
    main()
