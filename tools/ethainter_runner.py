#!/usr/bin/env python3
"""
ethainter_runner.py

Runs Ethainter via Gigahorse facts on SmartBugs-Curated-like dataset,
and evaluates against vulnerabilities.json using the SAME tool-agnostic metrics schema as other runners.

Per contract outputs:
- results/ethainter/<stem>.raw.txt
- results/ethainter/<stem>.json           (normalized schema: findings + detected_categories)
- results/ethainter/<stem>.meta.json

Aux outputs:
- results/ethainter/_rels/<stem>/

Evaluation:
- results/ethainter/evaluation_common.csv
- results/ethainter/evaluation_primary_by_category.csv
"""

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import time
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

SUPPORTED_CATEGORIES: Set[str] = {
    "reentrancy",
    "access_control",
    "arithmetic",
    "unchecked_low_level_calls",
    "denial_of_service",
    "front_running",
    "bad_randomness",
    "time_manipulation",
}

SOLC_VERSIONS = ["0.4.26", "0.5.17", "0.6.12", "0.7.6", "0.8.19"]

# ---------------- Paths ----------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

CONTRACT_DIR_DEFAULT = (REPO_ROOT / "dataset/smartbugs_curated").resolve()
OUTPUT_DIR_DEFAULT = (REPO_ROOT / "results/ethainter").resolve()

GT_CANDIDATES = [
    REPO_ROOT / "dataset/smartbugs_curated/vulnerabilities.json",
    REPO_ROOT / "dataset/smartbugs-curated/vulnerabilities.json",
]

CONTAINER_DEFAULT = (REPO_ROOT / "tools/containers/ethainter.sif").resolve()
APPTAINER_DEFAULT = "/apps/common/software/apptainer/1.4.0/bin/apptainer"

IN_CONTAINER_ETHAINTER_BIN = "/home/reviewer/ethainter-inlined.dl_compiled"
IN_CONTAINER_GIGAHORSE_DIR = "/home/reviewer/gigahorse-toolchain"


# ---------------- Utilities ----------------
def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_unlink(p: Path) -> None:
    try:
        p.unlink()
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
    return stem[len(cat) + 1 :]


def build_output_index(output_dir: Path) -> Dict[str, Path]:
    idx: Dict[str, Path] = {}
    for p in output_dir.glob("*.json"):
        if p.name.endswith(".meta.json"):
            continue
        stem = p.stem
        idx[stem] = p
        idx[strip_category_prefix(stem)] = p
    return idx


def write_triplet(output_dir: Path, stem: str, raw_text: str, payload: dict, meta: dict) -> None:
    (output_dir / f"{stem}.raw.txt").write_text(raw_text, encoding="utf-8", errors="ignore")
    (output_dir / f"{stem}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8", errors="ignore")
    (output_dir / f"{stem}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8", errors="ignore")


# ---------------- Ground Truth ----------------
def load_smartbugs_annotations(vuln_json: Path) -> Dict[str, Set[str]]:
    data = json.loads(vuln_json.read_text(errors="ignore"))
    gt: Dict[str, Set[str]] = defaultdict(set)

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue

            if "name" in item and "vulnerabilities" in item:
                stem = Path(item.get("name", "")).stem
                vulns = item.get("vulnerabilities") or []
                if stem and isinstance(vulns, list):
                    for v in vulns:
                        if isinstance(v, dict):
                            cat = v.get("category")
                            if cat:
                                gt[stem].add(cat)

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


def scan_meta_counts(contracts_dir: Path, output_dir: Path) -> Tuple[int, int, int, int, int]:
    sol_files = sorted(contracts_dir.rglob("*.sol"))
    contracts_total = len(sol_files)

    all_stems = {p.stem for p in sol_files}
    json_stems = {p.stem for p in output_dir.glob("*.json") if not p.name.endswith(".meta.json")}
    contracts_missing_output = len(all_stems - json_stems)

    success = 0
    empty = 0
    crash = 0

    for meta_path in output_dir.glob("*.meta.json"):
        try:
            m = json.loads(meta_path.read_text(errors="ignore"))
        except Exception:
            continue
        rc = int(m.get("returncode", 0))
        det = m.get("detected_categories", [])
        if rc != 0:
            crash += 1
        else:
            if det:
                success += 1
            else:
                empty += 1

    return contracts_total, success, crash, empty, contracts_missing_output


# ---------------- Tool Execution ----------------
def run_cmd(cmd: List[str], cwd: Optional[Path], timeout_s: int) -> Tuple[int, str]:
    try:
        out = subprocess.check_output(
            cmd,
            cwd=str(cwd) if cwd else None,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_s if timeout_s > 0 else None,
        )
        return 0, out
    except subprocess.CalledProcessError as e:
        return int(e.returncode), (e.output or "")
    except subprocess.TimeoutExpired as e:
        return 124, (e.output or "") + "\n[TIMEOUT]\n"
    except Exception as e:
        return 125, f"[EXCEPTION] {type(e).__name__}: {e}\n"


def apptainer_exec(apptainer_bin: str, container: Path, binds: List[Tuple[Path, str]], bash_cmd: str) -> List[str]:
    cmd = [apptainer_bin, "exec"]
    for host, mount in binds:
        cmd += ["--bind", f"{host}:{mount}"]
    cmd += [str(container), "bash", "-lc", bash_cmd]
    return cmd


# ---------------- solc-select helpers ----------------
def find_solc_select() -> Optional[str]:
    return shutil.which("solc-select")


def parse_pragma_version(src: str) -> Optional[str]:
    m = re.search(r"pragma\s+solidity\s+([^;]+);", src)
    return m.group(1).strip() if m else None


def choose_solc_for_pragma(pragma: Optional[str]) -> str:
    if not pragma:
        return "0.8.19"
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", pragma)
    if m:
        major = int(m.group(1))
        minor = int(m.group(2))
        if major == 0 and minor == 4:
            return "0.4.26"
        if major == 0 and minor == 5:
            return "0.5.17"
        if major == 0 and minor == 6:
            return "0.6.12"
        if major == 0 and minor == 7:
            return "0.7.6"
        if major == 0 and minor == 8:
            return "0.8.19"
    if "0.4" in pragma:
        return "0.4.26"
    if "0.5" in pragma:
        return "0.5.17"
    if "0.6" in pragma:
        return "0.6.12"
    if "0.7" in pragma:
        return "0.7.6"
    return "0.8.19"


def solc_select_use(solc_select_bin: str, version: str, timeout_s: int) -> Tuple[int, str]:
    return run_cmd([solc_select_bin, "use", version], cwd=None, timeout_s=timeout_s)


def solc_select_versions(solc_select_bin: str, timeout_s: int) -> Tuple[int, str]:
    return run_cmd([solc_select_bin, "versions"], cwd=None, timeout_s=timeout_s)


def solc_to_bytecode_hex(
    sol_path: Path,
    work_dir: Path,
    timeout_s: int,
    *,
    solc_cmd: str,
) -> Tuple[int, str, Optional[Path], Optional[str]]:
    logs: List[str] = []

    src = sol_path.read_text(errors="ignore")
    pragma = parse_pragma_version(src)
    want_ver = choose_solc_for_pragma(pragma)

    inp = {
        "language": "Solidity",
        "sources": {sol_path.name: {"content": src}},
        "settings": {"optimizer": {"enabled": False}, "outputSelection": {"*": {"*": ["evm.bytecode.object"]}}},
    }

    in_path = work_dir / "solc_input.json"
    bc_path = work_dir / "bytecode.hex"
    in_path.write_text(json.dumps(inp), encoding="utf-8")

    def extract(solc_out: str, origin: str) -> Tuple[int, str, Optional[Path], Optional[str]]:
        try:
            data = json.loads(solc_out)
        except Exception:
            return 4, f"COMPILE_FAIL({origin}): solc output not JSON\n" + solc_out[:2000], None, None

        bytecodes: Dict[str, str] = {}
        contracts = data.get("contracts", {}) or {}
        for _, file_v in contracts.items():
            for cname, cobj in (file_v or {}).items():
                bc = (((cobj or {}).get("evm") or {}).get("bytecode") or {}).get("object") or ""
                if isinstance(bc, str) and bc and bc != "0x":
                    bytecodes[cname] = bc[2:] if bc.startswith("0x") else bc

        if not bytecodes:
            errs = data.get("errors", [])
            err_txt = ""
            if isinstance(errs, list) and errs:
                msgs: List[str] = []
                for e in errs[:40]:
                    if isinstance(e, dict):
                        msgs.append(e.get("formattedMessage") or e.get("message") or str(e))
                    else:
                        msgs.append(str(e))
                err_txt = "\n".join(msgs)
            return 5, f"NO_BYTECODE\npragma={pragma}\n" + (err_txt + "\n" if err_txt else ""), None, None

        chosen = max(bytecodes.keys(), key=lambda k: len(bytecodes[k]))
        normalized = re.sub(r"\s+", "", bytecodes[chosen].strip())
        if normalized.startswith("0x"):
            normalized = normalized[2:]
        bc_path.write_text(normalized + "\n", encoding="utf-8")
        return 0, f"solc OK({origin}): chosen_contract={chosen}\n", bc_path, chosen

    solc_select_bin = find_solc_select()
    logs.append(f"[env] python={sys.executable}\n")
    logs.append(f"[pragma] {pragma}\n")
    logs.append(f"[choose] want_solc={want_ver}\n")

    if solc_select_bin:
        logs.append(f"[solc-select] using={solc_select_bin}\n")
        rc_u, out_u = solc_select_use(solc_select_bin, want_ver, timeout_s=60)
        logs.append(f"[solc-select use {want_ver}] rc={rc_u}\n{out_u}\n")
        if rc_u != 0:
            return 4, "".join(logs) + f"COMPILE_FAIL: solc-select use {want_ver} failed\n", None, None
    else:
        logs.append("[solc-select] NOT FOUND; using solc_cmd directly\n")

    cmd = ["bash", "-lc", f"{solc_cmd} --standard-json < {in_path}"]
    rc, out = run_cmd(cmd, cwd=work_dir, timeout_s=timeout_s)
    logs.append(f"[host solc_cmd='{solc_cmd}'] rc={rc}\n")
    if rc != 0:
        logs.append(out + "\n")
        return 4, "".join(logs) + "COMPILE_FAIL: host solc_cmd failed\n", None, None

    rc2, msg, bc, chosen = extract(out, f"host:{want_ver}")
    return rc2, "".join(logs) + msg, bc, chosen


# ---------------- Gigahorse (SUCCESS IF FACTS EXIST) ----------------
def _facts_present_tree(root: Path) -> bool:
    if not root.exists():
        return False
    for p in root.rglob("*"):
        try:
            if p.is_file() and p.stat().st_size > 0:
                return True
        except Exception:
            pass
    return False


def run_gigahorse_decompile_sh(
    apptainer_bin: str,
    container: Path,
    work: Path,
    run_id: str,
    timeout_s: int,
) -> Tuple[int, str]:
    binds = [(work, "/work")]
    bash_cmd = f"""
set +e
cd {IN_CONTAINER_GIGAHORSE_DIR} || exit 111
chmod -R a+rwx /work 2>/dev/null || true
bash -x ./decompile.sh -i /work/bytecode.hex -f /work/facts_root -o /work/gh_out --id "{run_id}"
rc=$?
echo "decompile_rc=$rc"
ls -la /work/facts_root/{run_id}_facts 2>/dev/null || true
exit $rc
""".strip()
    cmd = apptainer_exec(apptainer_bin, container, binds, bash_cmd)
    return run_cmd(cmd, cwd=work, timeout_s=timeout_s)


# =============================================================================
# RANKED MAPPING (THIS IS THE FIX THAT MAKES RQ2 MEANINGFUL)
# =============================================================================

# Map Ethainter vulnerability identifiers → SmartBugs categories (best-effort, regex-based).
# You can extend this safely as you observe more Ethainter vuln types in *_rels outputs.
VULN_TO_CAT_RULES: List[Tuple[str, str]] = [
    # Access control / authorization-like
    (r"(AccessibleSelfdestruct|TaintedOwnerVariable|Owner|OnlyOwner|Authorization|Auth)", "access_control"),
    # Unchecked low-level calls / delegatecall/staticcall/call return
    (r"(Unchecked|Staticcall|Delegatecall|CallReturn|LowLevel|ValueSend|TaintedValueSend)", "unchecked_low_level_calls"),
    # Arithmetic / bounds / index-ish
    (r"(Overflow|Underflow|Div0|Division|TaintedStoreIndex|OutOfBounds|Index)", "arithmetic"),
    # Reentrancy
    (r"(Reentr|Reentry|ReEnter)", "reentrancy"),
    # Time/bad randomness/front-running (rare in Ethainter, but keep hooks)
    (r"(Timestamp|TimeDepend|Now\b)", "time_manipulation"),
    (r"(Random|Blockhash|RNG)", "bad_randomness"),
    (r"(FrontRun|TOD|OrderingDepend|MEV)", "front_running"),
    # DoS-ish
    (r"(Denial|DOS|GasGrief|BlockGas|Grief)", "denial_of_service"),
]


def _map_vuln_name_to_category(vuln_name: str) -> str:
    for pat, cat in VULN_TO_CAT_RULES:
        if re.search(pat, vuln_name, flags=re.IGNORECASE):
            return cat
    return "other"


def _count_csv_data_rows(p: Path) -> int:
    """
    Counts non-empty CSV data rows (excluding header if present).
    Safe even if file has weird format or is empty.
    """
    try:
        txt = p.read_text(errors="ignore").strip()
    except Exception:
        return 0
    if not txt:
        return 0
    lines = [ln for ln in txt.splitlines() if ln.strip()]
    if not lines:
        return 0
    # Heuristic: if first line looks like header (contains letters and underscores), drop it.
    # Many Ethainter CSVs have no header; this still behaves reasonably.
    first = lines[0]
    if re.search(r"[A-Za-z_]", first) and ("\t" in first or "," in first):
        return max(0, len(lines) - 1)
    return len(lines)


def ranked_categories_from_relations(rel_dir: Path) -> List[Tuple[str, int]]:
    """
    Reads *_rels/<stem>/*.csv and returns a ranked list of (category, score).
    Score = summed evidence across Ethainter vuln CSVs mapped into that category.
    """
    if not rel_dir.exists():
        return []
    cat_scores: Dict[str, int] = defaultdict(int)

    for p in rel_dir.glob("*.csv"):
        name = p.name

        m = re.match(r"Vulnerability_(.+)\.csv$", name)
        if not m:
            m = re.match(r"VulnerabilityDescription_Vulnerability_(.+)\.csv$", name)
        if not m:
            continue

        vuln = m.group(1).strip()
        score = _count_csv_data_rows(p)
        if score <= 0:
            # still count presence as weak evidence (so ranked lists aren’t empty when files exist)
            score = 1

        cat = _map_vuln_name_to_category(vuln)
        cat_scores[cat] += score

    # Keep only SmartBugs cats + other, then rank by score desc
    filtered = [(c, s) for c, s in cat_scores.items() if c in SMARTBUGS_CATEGORIES]
    filtered.sort(key=lambda x: (-x[1], x[0]))
    return filtered


def normalize_payload_ranked(cat_ranked: List[Tuple[str, int]]) -> dict:
    """
    Produces findings ordered by score, which makes top-K metrics meaningful.
    """
    if not cat_ranked:
        return {"findings": [], "detected_categories": []}

    max_s = max(s for _, s in cat_ranked) if cat_ranked else 1
    findings = []
    detected = []
    for cat, s in cat_ranked:
        if cat not in SMARTBUGS_CATEGORIES:
            continue
        detected.append(cat)
        conf = min(1.0, float(s) / float(max_s)) if max_s else 1.0
        findings.append(
            {
                "category": cat,
                "severity": 1,
                "confidence": round(conf, 3),
                "title": cat,
                "rationale": f"Ranked via Ethainter relation evidence (score={s}).",
                "_score": int(s),  # harmless extra field; evaluator ignores unknown keys
            }
        )
    return {"findings": findings, "detected_categories": detected}


def categories_topk(findings: List[dict], k: int) -> Set[str]:
    top = (findings or [])[:k]
    cats: Set[str] = set()
    for f in top:
        c = f.get("category")
        if c in SMARTBUGS_CATEGORIES:
            cats.add(c)
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
    out_index = build_output_index(output_dir)

    scored = 0
    missing = 0
    micro = PRF(0, 0, 0)
    prf_at_k = {kk: PRF(0, 0, 0) for kk in K_LIST}

    for gt_stem, gt_cats in gt.items():
        out_file = out_index.get(gt_stem)
        if out_file is None or not out_file.exists():
            missing += 1
            continue

        try:
            payload = json.loads(out_file.read_text(errors="ignore"))
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

        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        for kk in K_LIST:
            pred_k = categories_topk(findings, kk)
            if supported_set is not None:
                pred_k = pred_k & supported_set
            prf_at_k[kk] = accumulate_micro_prf(gt_labels, pred_k, prf_at_k[kk])

    return scored, missing, micro, prf_at_k


def compute_primary_label_recall_table(gt: Dict[str, Set[str]], output_dir: Path) -> Dict[str, dict]:
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
        if out_file is None or not out_file.exists():
            by_cat[primary]["error"] += 1
            continue

        try:
            payload = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            by_cat[primary]["error"] += 1
            continue

        detected = set(payload.get("detected_categories", []))
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
    ap.add_argument("--output-dir", default=str(OUTPUT_DIR_DEFAULT))
    ap.add_argument("--gt", default="", help="Path to vulnerabilities.json (auto-detect if empty)")
    ap.add_argument("--evaluate", action="store_true", help="Run evaluation AFTER generation.")
    ap.add_argument("--evaluate-only", action="store_true", help="Skip generation; only evaluate existing outputs.")
    ap.add_argument("--clean", action="store_true")

    ap.add_argument("--container", default=str(CONTAINER_DEFAULT))
    ap.add_argument("--apptainer", default=APPTAINER_DEFAULT)
    ap.add_argument("--solc-cmd", default="solc")

    ap.add_argument("--timeout-solc", type=int, default=180)
    ap.add_argument("--timeout-gigahorse", type=int, default=1200)
    ap.add_argument("--timeout-souffle", type=int, default=1200)

    ap.add_argument("--one", default="", help="Run only one .sol file (name or relative path within contracts-dir).")
    ap.add_argument("--fail-fast", action="store_true")

    args = ap.parse_args()

    apptainer_bin = args.apptainer
    contracts_dir = Path(args.contracts_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    ensure_dir(output_dir)

    rels_root = output_dir / "_rels"
    ensure_dir(rels_root)

    do_eval = bool(args.evaluate or args.evaluate_only)
    do_generation = not args.evaluate_only

    if args.clean:
        for p in output_dir.glob("*"):
            if p.is_file():
                safe_unlink(p)
        if rels_root.exists():
            shutil.rmtree(rels_root)
        ensure_dir(rels_root)

    if args.one:
        one_path = (contracts_dir / args.one).resolve()
        if one_path.exists():
            contracts = [one_path]
        else:
            hits = [p for p in contracts_dir.rglob(args.one) if p.suffix == ".sol"]
            if not hits:
                raise FileNotFoundError(f"--one not found under {contracts_dir}: {args.one}")
            contracts = [hits[0]]
    else:
        contracts = sorted(contracts_dir.rglob("*.sol"))

    print(f"Found {len(contracts)} .sol files under {contracts_dir}")
    print(f"Output dir: {output_dir}")
    print(f"Mode: generation={do_generation} evaluate={do_eval} (evaluate_only={args.evaluate_only})")

    container = Path(args.container).resolve()
    if do_generation and not container.exists():
        raise FileNotFoundError(f"Ethainter container not found: {container}")
    if do_generation and (not apptainer_bin or not Path(apptainer_bin).exists()):
        raise RuntimeError(f"apptainer not found: {apptainer_bin}")

    success = 0
    empty = 0
    crash = 0

    if do_generation:
        for i, c in enumerate(contracts, 1):
            stem = c.stem
            rel = c.relative_to(contracts_dir)
            print(f"\n[{i}/{len(contracts)}] Running ethainter on {rel}...", flush=True)

            t0 = time.time()
            raw_parts: List[str] = []

            work = output_dir / "_work" / stem
            facts_root = work / "facts_root"
            gh_out = work / "gh_out"
            out_rel = rels_root / stem

            if work.exists():
                shutil.rmtree(work)
            ensure_dir(work)
            ensure_dir(facts_root)
            ensure_dir(gh_out)
            ensure_dir(out_rel)

            rc_solc, solc_log, bytecode_path, chosen_contract = solc_to_bytecode_hex(
                c, work, args.timeout_solc, solc_cmd=args.solc_cmd
            )
            raw_parts.append("=== SOLC ===\n" + solc_log)

            if rc_solc != 0 or bytecode_path is None:
                payload = {"findings": [], "detected_categories": []}
                meta = {
                    "tool": "ethainter",
                    "contract": str(rel),
                    "contract_stem": stem,
                    "returncode": rc_solc,
                    "detected_categories": [],
                    "num_findings": 0,
                    "elapsed_s": time.time() - t0,
                    "note": "solc_fail",
                    "chosen_contract": chosen_contract,
                }
                write_triplet(output_dir, stem, "\n".join(raw_parts), payload, meta)
                crash += 1
                print("[!] ethainter failed / solc", flush=True)
                if args.fail_fast:
                    break
                continue

            rc_gh, gh_log = run_gigahorse_decompile_sh(
                apptainer_bin=apptainer_bin,
                container=container,
                work=work,
                run_id=stem,
                timeout_s=args.timeout_gigahorse,
            )
            raw_parts.append("=== GIGAHORSE (decompile.sh) ===\n" + gh_log)

            facts_dir = facts_root / f"{stem}_facts"
            if not _facts_present_tree(facts_dir):
                payload = {"findings": [], "detected_categories": []}
                meta = {
                    "tool": "ethainter",
                    "contract": str(rel),
                    "contract_stem": stem,
                    "returncode": 7,
                    "detected_categories": [],
                    "num_findings": 0,
                    "elapsed_s": time.time() - t0,
                    "note": "gigahorse_no_facts",
                    "chosen_contract": chosen_contract,
                    "decompile_rc": rc_gh,
                }
                write_triplet(output_dir, stem, "\n".join(raw_parts), payload, meta)
                crash += 1
                print("[!] ethainter failed / gigahorse", flush=True)
                if args.fail_fast:
                    break
                continue

            binds = [(work, "/work"), (out_rel, "/work/out_rel")]
            souffle_cmd = f"set -euo pipefail; {IN_CONTAINER_ETHAINTER_BIN} -F /work/facts_root/{stem}_facts -D /work/out_rel"
            cmd = apptainer_exec(apptainer_bin, container, binds, souffle_cmd)
            rc_sf, sf_out = run_cmd(cmd, cwd=work, timeout_s=args.timeout_souffle)
            raw_parts.append(f"=== SOUFFLE ETHAINTER (rc={rc_sf}) ===\n{sf_out}\n")

            if rc_sf != 0:
                payload = {"findings": [], "detected_categories": []}
                meta = {
                    "tool": "ethainter",
                    "contract": str(rel),
                    "contract_stem": stem,
                    "returncode": 9,
                    "detected_categories": [],
                    "num_findings": 0,
                    "elapsed_s": time.time() - t0,
                    "note": "souffle_fail",
                    "chosen_contract": chosen_contract,
                    "decompile_rc": rc_gh,
                }
                write_triplet(output_dir, stem, "\n".join(raw_parts), payload, meta)
                crash += 1
                print("[!] ethainter failed / souffle", flush=True)
                if args.fail_fast:
                    break
                continue

            rel_files = [p for p in out_rel.glob("*") if p.is_file()]
            raw_parts.append(f"=== RELATIONS ===\ncount={len(rel_files)} files={[p.name for p in rel_files][:80]}\n")

            # >>> RANKED OUTPUT HERE <<<
            ranked = ranked_categories_from_relations(out_rel)
            payload = normalize_payload_ranked(ranked)

            if payload["detected_categories"]:
                success += 1
                note = "ranked_relations"
            else:
                empty += 1
                note = "empty_or_unmapped_relations"

            meta = {
                "tool": "ethainter",
                "contract": str(rel),
                "contract_stem": stem,
                "returncode": 0,
                "detected_categories": payload.get("detected_categories", []),
                "num_findings": len(payload.get("findings", [])),
                "elapsed_s": time.time() - t0,
                "note": note,
                "chosen_contract": chosen_contract,
                "decompile_rc": rc_gh,
                "relations_dir": str(out_rel),
                "relations_count": len(rel_files),
            }
            write_triplet(output_dir, stem, "\n".join(raw_parts), payload, meta)
            print("[✓] ethainter finished", flush=True)

        print("\n=== ethainter Run Summary ===")
        print(f"Success: {success}")
        print(f"Empty:   {empty}")
        print(f"Crash:   {crash}")
        print(f"Outputs: {output_dir}")

    if not do_eval:
        return

    gt_path = Path(args.gt).resolve() if args.gt else next((p for p in GT_CANDIDATES if p.exists()), Path(""))
    if not gt_path or not gt_path.exists():
        raise FileNotFoundError("Ground truth vulnerabilities.json not found. Pass --gt or place under dataset/smartbugs_curated/.")

    gt = load_smartbugs_annotations(gt_path)

    contracts_total, success_count, crash_count, empty_count, missing_output_count = scan_meta_counts(contracts_dir, output_dir)

    scored, missing_out, micro, prf_at_k = compute_micro_and_topk(gt, output_dir, supported_set=None)
    scored_s, missing_out_s, micro_s, prf_at_k_s = compute_micro_and_topk(gt, output_dir, supported_set=SUPPORTED_CATEGORIES)
    by_cat = compute_primary_label_recall_table(gt, output_dir)

    print("\n=== ethainter Evaluation (Category Labels) ===")
    print(f"Contracts scored: {scored}")
    print(f"Contracts missing output: {missing_out}")
    print(f"Micro-TP:{micro.tp} FP:{micro.fp} FN:{micro.fn}  P:{micro.precision:.2f} R:{micro.recall:.2f} F1:{micro.f1:.2f}")
    for kk in K_LIST:
        m = prf_at_k[kk]
        print(f"P@{kk}:{m.precision:.2f} R@{kk}:{m.recall:.2f} F1@{kk}:{m.f1:.2f}")

    print("\n=== ethainter Coverage-Aware (Supported Only) ===")
    print(f"Supported categories: {sorted(SUPPORTED_CATEGORIES)}")
    print(f"Contracts scored: {scored_s}")
    print(f"Contracts missing output: {missing_out_s}")
    print(f"Micro-TP:{micro_s.tp} FP:{micro_s.fp} FN:{micro_s.fn}  P:{micro_s.precision:.2f} R:{micro_s.recall:.2f} F1:{micro_s.f1:.2f}")
    for kk in K_LIST:
        m = prf_at_k_s[kk]
        print(f"Supported P@{kk}:{m.precision:.2f} R@{kk}:{m.recall:.2f} F1@{kk}:{m.f1:.2f}")

    print("\n=== ethainter Per-Category Recall (Primary Label) ===")
    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        print(f"{cat} Total:{s['total']} Correct:{s['correct']} Missed:{s['missed']} Error:{s['error']} Recall:{s['recall']:.2f}")

    out_csv = output_dir / "evaluation_common.csv"
    headers = [
        "tool","contracts_total","contracts_success","contracts_crash","contracts_empty",
        "contracts_scored","contracts_missing_output","supported_categories",
        "micro_tp","micro_fp","micro_fn","micro_precision","micro_recall","micro_f1",
        "supported_tp","supported_fp","supported_fn","supported_precision","supported_recall","supported_f1",
        "primary_total_scored","primary_missing_output",
    ]
    for kk in K_LIST:
        headers += [f"p_at_{kk}", f"r_at_{kk}", f"f1_at_{kk}"]
    for kk in K_LIST:
        headers += [f"supported_p_at_{kk}", f"supported_r_at_{kk}", f"supported_f1_at_{kk}"]

    primary_total_scored = sum(by_cat[c]["total"] for c in SMARTBUGS_CATEGORIES)
    primary_missing_output = sum(by_cat[c]["error"] for c in SMARTBUGS_CATEGORIES)

    row = {
        "tool":"ethainter",
        "contracts_total":contracts_total,
        "contracts_success":success_count,
        "contracts_crash":crash_count,
        "contracts_empty":empty_count,
        "contracts_scored":scored,
        "contracts_missing_output":missing_out,
        "supported_categories":"|".join(sorted(SUPPORTED_CATEGORIES)),
        "micro_tp":micro.tp, "micro_fp":micro.fp, "micro_fn":micro.fn,
        "micro_precision":f"{micro.precision:.6f}", "micro_recall":f"{micro.recall:.6f}", "micro_f1":f"{micro.f1:.6f}",
        "supported_tp":micro_s.tp, "supported_fp":micro_s.fp, "supported_fn":micro_s.fn,
        "supported_precision":f"{micro_s.precision:.6f}", "supported_recall":f"{micro_s.recall:.6f}", "supported_f1":f"{micro_s.f1:.6f}",
        "primary_total_scored":primary_total_scored,
        "primary_missing_output":primary_missing_output,
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

    out_primary = output_dir / "evaluation_primary_by_category.csv"
    with open(out_primary, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool","category","total","correct","missed","error","recall"])
        for cat in SMARTBUGS_CATEGORIES:
            s = by_cat[cat]
            w.writerow(["ethainter", cat, s["total"], s["correct"], s["missed"], s["error"], f"{s['recall']:.6f}"])

    print(f"\nWrote: {out_csv}")
    print(f"Wrote: {out_primary}")


if __name__ == "__main__":
    main()
