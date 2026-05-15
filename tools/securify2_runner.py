#!/usr/bin/env python3
"""
securify2_runner.py

Runs Securify2 on SmartBugs-Curated-like dataset and evaluates results using the SAME
tool-agnostic schema as smartcheck_runner.py / mythril_runner.py.

Default:
- Contracts:  dataset/smartbugs_curated/**/*.sol
- Runner:     docker run ... securify2 (recommended) OR local `securify`
- Outputs:    results/securify2/<contract_stem>.json + .raw.txt

Evaluation (--evaluate):
- Writes results/securify2/evaluation_common.csv with a tool-agnostic schema:
  * Failure counts (crash/empty/success)
  * Micro P/R/F1 on category labels (multi-label)
  * Coverage-aware micro P/R/F1 restricted to supported categories
  * Precision@K / Recall@K / F1@K for K in {1,3,5,10} (also coverage-aware versions)
  * Primary-label per-category recall CSV (SmartBugs primary label per contract)

Important:
- Securify2 supports Solidity >= 0.5.8 (per upstream README). Contracts below that
  will often fail compilation inside the default docker image.
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


# ---------------- Pattern -> Category Mapping ----------------
# Securify2 reports "patterns". Map those patterns to SmartBugs categories.
# Keep conservative; you can expand after you inspect your outputs.
#
# Pattern list is in upstream README (TOD*, DAO, Timestamp, UnhandledException, etc.).
# We'll map the most relevant ones to SmartBugs categories.
SECURIFY_PATTERN_TO_CATEGORY: Dict[str, str] = {
    # Reentrancy family
    "DAO": "reentrancy",
    "ReentrancyNoETH": "reentrancy",
    "ReentrancyBenign": "reentrancy",

    # Time manipulation
    "Timestamp": "time_manipulation",

    # Front-running / TOD
    "TODAmount": "front_running",
    "TODReceiver": "front_running",
    "TODTransfer": "front_running",

    # Low-level calls / unchecked results
    "UnhandledException": "unchecked_low_level_calls",
    "LowLevelCalls": "unchecked_low_level_calls",
    "UnusedReturn": "unchecked_low_level_calls",
    "UnrestrictedEtherFlow": "unchecked_low_level_calls",

    # Denial of service
    "CallInLoop": "denial_of_service",

    # Bad randomness (blockhash misuse sometimes surfaces here; Securify2 has no explicit "Random" pattern in table,
    # but keep placeholder for future if you see one.)
    # "BadRandomness": "bad_randomness",

    # Access control / authorization-ish
    "TxOrigin": "access_control",
    "UnrestrictedWrite": "access_control",
    "UnrestrictedDelegateCall": "access_control",
    "UnrestrictedSelfdestruct": "access_control",

    # "Short address" is typically older ERC20 bug; Securify2 may not report it directly.
    # Arithmetic: Securify2 focuses less on overflow/underflow than Mythril; keep none unless observed.
}

SUPPORTED_CATEGORIES: Set[str] = set(SECURIFY_PATTERN_TO_CATEGORY.values())


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


def extract_pragma_version(source_text: str) -> Optional[Tuple[int, int, int]]:
    """
    Best-effort parse of pragma solidity. We only need to decide if it's <0.5.8 in many cases.
    Returns (major, minor, patch) if found.
    """
    m = re.search(r"pragma\s+solidity\s+([^;]+);", source_text)
    if not m:
        return None
    pragma = m.group(1)
    # find first X.Y.Z
    m2 = re.search(r"(\d+)\.(\d+)\.(\d+)", pragma)
    if not m2:
        return None
    return int(m2.group(1)), int(m2.group(2)), int(m2.group(3))


def version_lt(a: Tuple[int, int, int], b: Tuple[int, int, int]) -> bool:
    return a < b


# ---------------- Running Securify2 ----------------
def run_securify2_docker(
    contract_path: Path,
    contracts_mount_dir: Path,
    docker_image: str,
    timeout_s: Optional[int],
) -> Tuple[int, str, str]:
    """
    Run: docker run --rm -v <contracts_mount_dir>:/share <image> /share/<relative_path>
    """
    rel = contract_path.relative_to(contracts_mount_dir)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{str(contracts_mount_dir)}:/share",
        docker_image,
        f"/share/{str(rel)}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def run_securify2_local(
    contract_path: Path,
    securify_cmd: str,
    timeout_s: Optional[int],
) -> Tuple[int, str, str]:
    """
    Run local CLI: securify <contract>.sol
    """
    cmd = securify_cmd.split() + [str(contract_path)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


# ---------------- Parsing output ----------------
# Securify2 stdout is typically human-readable, sometimes containing pattern sections.
# We parse pattern names from the known list, and try to extract a "count" of violations if present.
#
# This is intentionally robust:
# - if we see the pattern name anywhere, we treat it as a "hit"
# - if we can parse counts, we store them
PATTERN_NAMES = sorted(SECURIFY_PATTERN_TO_CATEGORY.keys(), key=len, reverse=True)

_COUNT_RE = re.compile(r"(violations?|violation|warning|warnings|found)\s*[:=]?\s*(\d+)", re.IGNORECASE)

def parse_securify2_output(stdout: str, stderr: str) -> List[dict]:
    """
    Returns a list of findings dicts with:
      - pattern
      - severity (best-effort: Critical/High/Medium/Low/Info -> 5..1)
      - count (best-effort)
      - raw_snippet
    If we can't parse anything meaningful, returns [].
    """
    text = (stdout or "") + "\n" + (stderr or "")
    findings: List[dict] = []

    # Best-effort severity mapping if printed
    sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    for pname in PATTERN_NAMES:
        # look for pattern name as a whole word-ish token
        if re.search(rf"\b{re.escape(pname)}\b", text):
            # grab a small neighborhood for evidence
            m = re.search(rf"(.{{0,120}}\b{re.escape(pname)}\b.{{0,120}})", text, re.DOTALL)
            snippet = m.group(1).strip() if m else pname

            # parse severity if present near snippet
            sev = 0
            msev = re.search(r"(Critical|High|Medium|Low|Info)", snippet, re.IGNORECASE)
            if msev:
                sev = sev_map.get(msev.group(1).lower(), 0)

            # parse a count if present near snippet
            cnt = None
            mc = _COUNT_RE.search(snippet)
            if mc:
                try:
                    cnt = int(mc.group(2))
                except Exception:
                    cnt = None

            findings.append({
                "pattern": pname,
                "severity": sev,
                "count": cnt,
                "raw": snippet,
            })

    return findings


def finding_categories(f: dict) -> Set[str]:
    pname = f.get("pattern")
    if not pname:
        return set()
    mapped = SECURIFY_PATTERN_TO_CATEGORY.get(pname)
    return {mapped} if mapped else set()


def contract_detected_categories(findings: List[dict]) -> Set[str]:
    out: Set[str] = set()
    for f in findings:
        out |= finding_categories(f)
    return out


def contract_detected_categories_topk(findings: List[dict], k: int) -> Set[str]:
    """
    Rank findings by severity desc, then count desc (if available), stable by pattern.
    """
    def key(f: dict):
        sev = int(f.get("severity") or 0)
        cnt = f.get("count")
        cntv = int(cnt) if isinstance(cnt, int) else 0
        return (sev, cntv, f.get("pattern",""))
    ordered = sorted(findings, key=key, reverse=True)
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


def pick_primary_gt_category(stem: str, gt_cats: Set[str]) -> Optional[str]:
    """
    Match your Solhint-style table:
    - primary label is inferred from filename prefix if present
    - else if exactly one GT cat, use it
    """
    c = infer_category_from_filename(stem)
    if c:
        return c
    only = [x for x in gt_cats if x in SMARTBUGS_CATEGORIES]
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


def accumulate_micro_prf(gt_labels: Set[str], pred_labels: Set[str], prf: PRF) -> PRF:
    tp = len(gt_labels & pred_labels)
    fp = len(pred_labels - gt_labels)
    fn = len(gt_labels - pred_labels)
    return PRF(prf.tp + tp, prf.fp + fp, prf.fn + fn)


def compute_metrics_from_outputs(
    gt: Dict[str, Set[str]],
    output_dir: Path,
    supported_set: Optional[Set[str]] = None,
) -> Tuple[int, int, PRF, Dict[int, PRF]]:
    out_index = build_output_index(output_dir)

    scored = 0
    missing = 0
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
            missing += 1
            continue

        try:
            payload = json.loads(out_file.read_text(errors="ignore"))
            findings = payload.get("findings", [])
        except Exception:
            missing += 1
            continue

        gt_labels = {c for c in gt_cats if c in SMARTBUGS_CATEGORIES}
        pred_labels = set(payload.get("detected_categories", []))

        if supported_set is not None:
            gt_labels = gt_labels & supported_set
            pred_labels = pred_labels & supported_set

        scored += 1
        micro = accumulate_micro_prf(gt_labels, pred_labels, micro)

        for k in K_LIST:
            pred_k = contract_detected_categories_topk(findings, k)
            if supported_set is not None:
                pred_k = pred_k & supported_set
            prf_at_k[k] = accumulate_micro_prf(gt_labels, pred_k, prf_at_k[k])

    return scored, missing, micro, prf_at_k


def compute_primary_label_recall(
    gt: Dict[str, Set[str]],
    output_dir: Path,
) -> Tuple[int, int, Dict[str, dict]]:
    """
    Produces Solhint-like primary-label recall table:
    Category | Total | Correct | Missed | Error | Recall
    Correct = primary label is in predicted set
    Missed  = output exists but primary label not predicted
    Error   = no output
    """
    out_index = build_output_index(output_dir)

    primary_total_scored = 0
    primary_missing_output = 0
    by_cat = defaultdict(lambda: {"total": 0, "correct": 0, "missed": 0, "error": 0})

    for stem, gt_cats in gt.items():
        primary = pick_primary_gt_category(stem, gt_cats)
        if not primary:
            continue  # skip ambiguous
        by_cat[primary]["total"] += 1

        out_file = out_index.get(stem)
        if out_file is None:
            for cat in SMARTBUGS_CATEGORIES_SORTED:
                cand = f"{cat}_{stem}"
                if cand in out_index:
                    out_file = out_index[cand]
                    break

        if out_file is None or not out_file.exists():
            by_cat[primary]["error"] += 1
            primary_missing_output += 1
            continue

        try:
            payload = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            by_cat[primary]["error"] += 1
            primary_missing_output += 1
            continue

        primary_total_scored += 1
        pred = set(payload.get("detected_categories", []))
        if primary in pred:
            by_cat[primary]["correct"] += 1
        else:
            by_cat[primary]["missed"] += 1

    return primary_total_scored, primary_missing_output, by_cat


# ---------------- Main ----------------
def main():
    repo_root = Path(__file__).resolve().parent.parent  # tools/ -> repo root

    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts-dir", default=str((repo_root / "dataset/smartbugs_curated").resolve()))
    ap.add_argument("--output-dir", default=str((repo_root / "results/securify2").resolve()))
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--gt", default="", help="Path to vulnerabilities.json (auto-detect if empty)")

    # runner selection
    ap.add_argument("--mode", choices=["docker", "local"], default="docker")
    ap.add_argument("--docker-image", default="securify2")
    ap.add_argument("--securify-cmd", default="securify")

    # housekeeping
    ap.add_argument("--clean", action="store_true")
    args = ap.parse_args()

    contracts_dir = Path(args.contracts_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    if not contracts_dir.exists():
        raise FileNotFoundError(f"Contracts directory not found: {contracts_dir}")
    ensure_dir(output_dir)

    if args.clean:
        for pat in ["*.json", "*.raw.txt", "*.error.txt", "*.csv"]:
            for f in output_dir.glob(pat):
                try:
                    f.unlink()
                except Exception:
                    pass

    gt_candidates = [
        repo_root / "dataset/smartbugs_curated/vulnerabilities.json",
        repo_root / "dataset/smartbugs-curated/vulnerabilities.json",
    ]
    gt_path = Path(args.gt).resolve() if args.gt else next((p for p in gt_candidates if p.exists()), Path(""))

    contracts = sorted(contracts_dir.rglob("*.sol"))
    print(f"Found {len(contracts)} .sol files under {contracts_dir}")

    crash = 0
    empty = 0
    success = 0

    # (optional) overall counts of findings for summary
    total_findings = 0

    for i, c in enumerate(contracts, 1):
        rel = c.relative_to(contracts_dir)
        print(f"\n[{i}/{len(contracts)}] Evaluating {rel}...")

        # quick pragma gate: note Securify2 supports >=0.5.8, but we still *try* running;
        # many older contracts will crash -> reflected in crash counts.
        src = ""
        try:
            src = c.read_text(errors="ignore")
        except Exception:
            pass
        v = extract_pragma_version(src)
        if v and version_lt(v, (0, 5, 8)):
            # This is very likely to fail in docker image; still try if you want full transparency.
            pass

        if args.mode == "docker":
            rc, out, err = run_securify2_docker(
                c, contracts_dir, args.docker_image, args.timeout
            )
        else:
            rc, out, err = run_securify2_local(
                c, args.securify_cmd, args.timeout
            )

        # Always write raw output
        raw_path = output_dir / f"{c.stem}.raw.txt"
        raw_path.write_text(
            f"RETURN_CODE:\n{rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n",
            encoding="utf-8",
            errors="ignore",
        )

        findings = parse_securify2_output(out, err)

        # classify crash: nonzero and no parseable findings
        if rc != 0 and len(findings) == 0:
            crash += 1
            (output_dir / f"{c.stem}.error.txt").write_text(
                err or out or "",
                encoding="utf-8",
                errors="ignore",
            )
            print("[!] Securify2 crash / no parseable findings")
            continue

        # empty: ran but no findings parsed
        if len(findings) == 0:
            empty += 1
        else:
            success += 1

        det_cats = sorted(contract_detected_categories(findings))

        payload = {
            "tool": "securify2",
            "contract": str(rel),
            "contract_stem": c.stem,
            "returncode": rc,
            "findings": findings,
            "detected_categories": det_cats,
        }
        (output_dir / f"{c.stem}.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        total_findings += len(findings)
        print(f"[✓] Parsed findings={len(findings)} detected_categories={det_cats}")

    print("\n=== Securify2 Run Summary ===")
    print(f"Success: {success}")
    print(f"Empty:   {empty}")
    print(f"Crash:   {crash}")
    print(f"Outputs: {output_dir}")

    denom = success + empty
    if denom:
        print("\n=== Securify2 Findings Summary ===")
        print(f"Total findings (pattern hits): {total_findings}")
        print(f"Avg findings/contract: {total_findings / denom:.2f}")

    if not args.evaluate:
        return

    if not gt_path or not gt_path.exists():
        raise FileNotFoundError(
            "Ground truth vulnerabilities.json not found. "
            "Pass --gt /path/to/vulnerabilities.json or place it under dataset/smartbugs_curated/."
        )

    gt = load_smartbugs_annotations(gt_path)

    # Overall micro + @K
    scored, missing, micro, prf_at_k = compute_metrics_from_outputs(gt, output_dir, supported_set=None)

    # Coverage-aware micro + @K
    scored_s, missing_s, micro_s, prf_at_k_s = compute_metrics_from_outputs(gt, output_dir, supported_set=SUPPORTED_CATEGORIES)

    # Primary-label per-category recall
    primary_total_scored, primary_missing_output, primary_by_cat = compute_primary_label_recall(gt, output_dir)

    print("\n=== Securify2 Evaluation (Category Labels) ===")
    print(f"Contracts scored: {scored}")
    print(f"Contracts missing output: {missing}")
    print(f"Micro-TP:{micro.tp} FP:{micro.fp} FN:{micro.fn}  P:{micro.precision:.2f} R:{micro.recall:.2f} F1:{micro.f1:.2f}")
    for k in K_LIST:
        m = prf_at_k[k]
        print(f"P@{k}:{m.precision:.2f} R@{k}:{m.recall:.2f} F1@{k}:{m.f1:.2f}")

    print("\n=== Securify2 Coverage-Aware (Supported Only) ===")
    print(f"Supported categories: {sorted(SUPPORTED_CATEGORIES)}")
    print(f"Contracts scored: {scored_s}")
    print(f"Contracts missing output: {missing_s}")
    print(f"Micro-TP:{micro_s.tp} FP:{micro_s.fp} FN:{micro_s.fn}  P:{micro_s.precision:.2f} R:{micro_s.recall:.2f} F1:{micro_s.f1:.2f}")
    for k in K_LIST:
        m = prf_at_k_s[k]
        print(f"Supported P@{k}:{m.precision:.2f} R@{k}:{m.recall:.2f} F1@{k}:{m.f1:.2f}")

    print("\n=== Securify2 Per-Category Recall (Primary Label) ===")
    for cat in SMARTBUGS_CATEGORIES:
        s = primary_by_cat.get(cat, {"total": 0, "correct": 0, "missed": 0, "error": 0})
        total = s["total"]
        correct = s["correct"]
        missed_c = s["missed"]
        err_c = s["error"]
        rec = (correct / total) if total else 0.0
        print(f"{cat} Total:{total} Correct:{correct} Missed:{missed_c} Error:{err_c} Recall:{rec:.2f}")

    # Write common CSV schema (same columns as your current evaluation_common.csv)
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

    row = {
        "tool": "securify2",
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

    # Primary-label table CSV (for LaTeX table creation)
    out_primary = output_dir / "evaluation_primary_by_category.csv"
    with open(out_primary, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "category", "total", "correct", "missed", "error", "recall"])
        for cat in SMARTBUGS_CATEGORIES:
            s = primary_by_cat.get(cat, {"total": 0, "correct": 0, "missed": 0, "error": 0})
            total = s["total"]
            correct = s["correct"]
            missed_c = s["missed"]
            err_c = s["error"]
            rec = (correct / total) if total else 0.0
            w.writerow(["securify2", cat, total, correct, missed_c, err_c, f"{rec:.4f}"])

    print(f"\nWrote: {out_csv}")
    print(f"Wrote: {out_primary}")


if __name__ == "__main__":
    main()
