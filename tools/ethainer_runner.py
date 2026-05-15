#!/usr/bin/env python3
"""
ethainter_runner.py

Runs Ethainter (Soufflé Datalog semantic analyzer) using Gigahorse FACT GENERATION ONLY
(bypasses decompile.sh which fails at souffle decompiler.dl in this container),
then evaluates against vulnerabilities.json in the same schema as other runners.

Per contract outputs (always written):
- results/ethainter/<stem>.raw.txt
- results/ethainter/<stem>.json
- results/ethainter/<stem>.meta.json

Aux outputs:
- results/ethainter/_rels/<stem>/   (relation files emitted by Ethainter)
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


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


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_unlink(p: Path) -> None:
    try:
        p.unlink()
    except Exception:
        pass


def chmod_tree_writable(p: Path) -> None:
    try:
        if not p.exists():
            return
        for root, dirs, files in os.walk(p):
            for d in dirs:
                try:
                    Path(root, d).chmod(0o777)
                except Exception:
                    pass
            for f in files:
                try:
                    Path(root, f).chmod(0o666)
                except Exception:
                    pass
        try:
            p.chmod(0o777)
        except Exception:
            pass
    except Exception:
        pass


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

    solc_select_bin = find_solc_select()
    logs.append(f"[env] python={sys.executable}\n")
    logs.append(f"[pragma] {pragma}\n")
    logs.append(f"[choose] want_solc={want_ver}\n")

    if solc_select_bin:
        rc_v, out_v = solc_select_versions(solc_select_bin, timeout_s=30)
        logs.append(f"[solc-select versions] rc={rc_v}\n{out_v}\n")
        rc_u, out_u = solc_select_use(solc_select_bin, want_ver, timeout_s=60)
        logs.append(f"[solc-select use {want_ver}] rc={rc_u}\n{out_u}\n")
        if rc_u != 0:
            return 4, "".join(logs) + "COMPILE_FAIL: solc-select use failed\n", None, None

    rc, out = run_cmd(["bash", "-lc", f"{solc_cmd} --standard-json < {in_path}"], cwd=work_dir, timeout_s=timeout_s)
    logs.append(f"[host solc] rc={rc}\n{out}\n")
    if rc != 0:
        return 4, "".join(logs) + "COMPILE_FAIL: solc failed\n", None, None

    try:
        data = json.loads(out)
    except Exception:
        return 4, "".join(logs) + "COMPILE_FAIL: solc output not JSON\n", None, None

    bytecodes: Dict[str, str] = {}
    contracts = data.get("contracts", {}) or {}
    for _, file_v in contracts.items():
        for cname, cobj in (file_v or {}).items():
            bc = (((cobj or {}).get("evm") or {}).get("bytecode") or {}).get("object") or ""
            if isinstance(bc, str) and bc and bc != "0x":
                bytecodes[cname] = bc[2:] if bc.startswith("0x") else bc

    if not bytecodes:
        return 5, "".join(logs) + "NO_BYTECODE\n", None, None

    chosen = max(bytecodes.keys(), key=lambda k: len(bytecodes[k]))
    normalized = re.sub(r"\s+", "", bytecodes[chosen].strip())
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    bc_path.write_text(normalized + "\n", encoding="utf-8")
    try:
        bc_path.chmod(0o666)
    except Exception:
        pass

    logs.append(f"solc OK(host:{want_ver}): chosen_contract={chosen} contracts={list(bytecodes.keys())}\n")
    return 0, "".join(logs), bc_path, chosen


def facts_present(dir_path: Path) -> bool:
    if not dir_path.exists():
        return False
    for p in dir_path.glob("*"):
        if p.is_file() and p.stat().st_size > 0:
            return True
    return False


def run_generatefacts_only(
    apptainer_bin: str,
    container: Path,
    work: Path,
    timeout_s: int,
) -> Tuple[int, str]:
    """
    Generates gigahorse facts only (no decompiler Soufflé stage).
    Writes facts into /work/facts (host: work/facts).
    """
    facts = work / "facts"
    ensure_dir(facts)
    chmod_tree_writable(work)
    chmod_tree_writable(facts)

    binds = [(work, "/work")]

    bash_cmd = r"""
set +e
echo "== id =="; id || true
echo "== pwd =="; pwd
echo "== /work =="; ls -la /work | head -n 120 || true
chmod -R a+rwx /work 2>/dev/null || true

cd """ + IN_CONTAINER_GIGAHORSE_DIR + r""" || exit 111

echo "== locate generatefacts ==";
ls -la bin/generatefacts 2>/dev/null || true
ls -la logic/../bin/generatefacts 2>/dev/null || true

echo "== RUN generatefacts ONLY =="
rm -rf /work/facts/* 2>/dev/null || true
cd logic || exit 112
../bin/generatefacts /work/bytecode.hex /work/facts
rc=$?
echo "generatefacts_rc=$rc"
echo "== facts listing =="
ls -la /work/facts | head -n 200 || true
exit $rc
"""
    cmd = apptainer_exec(apptainer_bin, container, binds, bash_cmd)
    rc, out = run_cmd(cmd, cwd=work, timeout_s=timeout_s)

    if rc != 0:
        return 7, out + "\n[gigahorse] FAILED: generatefacts non-zero\n"
    if not facts_present(facts):
        return 8, out + "\n[gigahorse] FAILED: NO_FACTS produced\n"
    return 0, out + "\n[gigahorse] SUCCESS\n"


RELATION_MAP: Dict[str, List[str]] = {
    "reentrancy": [r"reentr", r"re_enter", r"call_cycle", r"reentry"],
    "access_control": [r"auth", r"authoriz", r"onlyowner", r"privilege", r"owner", r"role"],
    "arithmetic": [r"overflow", r"underflow", r"arith", r"div0", r"division_by_zero"],
    "unchecked_low_level_calls": [r"unchecked", r"unchecked_call", r"ignored_return", r"low_level_call", r"call_return"],
    "denial_of_service": [r"\bdos\b", r"denial", r"gas_grief", r"grief", r"block_gas"],
    "front_running": [r"front.?run", r"\btod\b", r"ordering_depend", r"mev", r"sandwich"],
    "bad_randomness": [r"random", r"blockhash", r"rng", r"weak_random"],
    "time_manipulation": [r"timestamp", r"time_depend", r"block\.timestamp", r"\bnow\b"],
}


def map_relations_to_categories(rel_dir: Path) -> Set[str]:
    cats: Set[str] = set()
    files = [p.name for p in rel_dir.glob("*") if p.is_file()]
    if not files:
        return cats
    for cat, pats in RELATION_MAP.items():
        for fn in files:
            for pat in pats:
                if re.search(pat, fn, flags=re.IGNORECASE):
                    cats.add(cat)
                    break
            if cat in cats:
                break
    return cats


def normalize_payload(detected_categories: Set[str]) -> dict:
    det = sorted([c for c in detected_categories if c in SMARTBUGS_CATEGORIES])
    findings = [
        {
            "category": c,
            "severity": 1,
            "confidence": 1,
            "title": c,
            "rationale": "Detected via Ethainter relation output.",
        }
        for c in det
    ]
    return {"findings": findings, "detected_categories": det}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts-dir", default=str(CONTRACT_DIR_DEFAULT))
    ap.add_argument("--output-dir", default=str(OUTPUT_DIR_DEFAULT))
    ap.add_argument("--clean", action="store_true")

    ap.add_argument("--container", default=str(CONTAINER_DEFAULT))
    ap.add_argument("--apptainer", default=APPTAINER_DEFAULT)
    ap.add_argument("--solc-cmd", default="solc")

    ap.add_argument("--timeout-solc", type=int, default=180)
    ap.add_argument("--timeout-gigahorse", type=int, default=1200)
    ap.add_argument("--timeout-ethainter", type=int, default=1200)

    ap.add_argument("--fail-fast", action="store_true")
    ap.add_argument("--one", default="", help="Run only one .sol (relative to contracts-dir or absolute).")

    args = ap.parse_args()

    contracts_dir = Path(args.contracts_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    ensure_dir(output_dir)

    rels_root = output_dir / "_rels"
    ensure_dir(rels_root)

    if args.clean:
        for p in output_dir.glob("*"):
            if p.is_file():
                safe_unlink(p)
        shutil.rmtree(rels_root, ignore_errors=True)
        ensure_dir(rels_root)
        shutil.rmtree(output_dir / "_work", ignore_errors=True)

    container = Path(args.container).resolve()
    apptainer_bin = args.apptainer
    if not container.exists():
        raise FileNotFoundError(f"Container not found: {container}")
    if not Path(apptainer_bin).exists():
        raise FileNotFoundError(f"Apptainer not found: {apptainer_bin}")

    if args.one:
        p = Path(args.one)
        if not p.is_absolute():
            p = contracts_dir / p
        contracts = [p.resolve()]
    else:
        contracts = sorted(contracts_dir.rglob("*.sol"))

    print(f"Found {len(contracts)} .sol files under {contracts_dir}")
    print(f"Output dir: {output_dir}")
    print(f"Mode: generation=True evaluate=False (evaluate_only=False)")

    for i, sol_file in enumerate(contracts, 1):
        stem = sol_file.stem
        rel = sol_file.relative_to(contracts_dir) if sol_file.is_relative_to(contracts_dir) else sol_file

        print(f"\n[{i}/{len(contracts)}] Running ethainter on {rel}...", flush=True)
        t0 = time.time()
        raw_parts: List[str] = []

        work = output_dir / "_work" / stem
        facts = work / "facts"
        out_rel = rels_root / stem

        shutil.rmtree(work, ignore_errors=True)
        ensure_dir(work)
        ensure_dir(facts)
        ensure_dir(out_rel)
        chmod_tree_writable(work)
        chmod_tree_writable(out_rel)

        # solc
        rc_solc, solc_log, bytecode_path, chosen_contract = solc_to_bytecode_hex(
            sol_file, work, args.timeout_solc, solc_cmd=args.solc_cmd
        )
        raw_parts.append("=== SOLC ===\n" + solc_log)

        if rc_solc != 0 or bytecode_path is None:
            print("[!] ethainter failed / solc", flush=True)
            write_triplet(
                output_dir,
                stem,
                "\n".join(raw_parts),
                {"findings": [], "detected_categories": []},
                {
                    "tool": "ethainter",
                    "contract": str(rel),
                    "contract_stem": stem,
                    "returncode": rc_solc,
                    "detected_categories": [],
                    "num_findings": 0,
                    "elapsed_s": time.time() - t0,
                    "note": "solc_fail",
                    "chosen_contract": chosen_contract,
                },
            )
            if args.fail_fast:
                return
            continue

        # gigahorse facts ONLY (fixed)
        rc_gh, gh_log = run_generatefacts_only(
            apptainer_bin=apptainer_bin,
            container=container,
            work=work,
            timeout_s=args.timeout_gigahorse,
        )
        raw_parts.append("=== GIGAHORSE (generatefacts only) ===\n" + gh_log)

        if rc_gh != 0:
            print("[!] ethainter failed / gigahorse(generatefacts)", flush=True)
            write_triplet(
                output_dir,
                stem,
                "\n".join(raw_parts),
                {"findings": [], "detected_categories": []},
                {
                    "tool": "ethainter",
                    "contract": str(rel),
                    "contract_stem": stem,
                    "returncode": rc_gh,
                    "detected_categories": [],
                    "num_findings": 0,
                    "elapsed_s": time.time() - t0,
                    "note": "gigahorse_generatefacts_fail",
                },
            )
            if args.fail_fast:
                return
            continue

        # ethainter (souffle compiled)
        binds = [(work, "/work"), (out_rel, "/work/out_rel")]
        eth_cmd = "set -euo pipefail; " + IN_CONTAINER_ETHAINTER_BIN + " -F /work/facts -D /work/out_rel"
        cmd = apptainer_exec(apptainer_bin, container, binds, eth_cmd)
        rc_e, e_out = run_cmd(cmd, cwd=work, timeout_s=args.timeout_ethainter)
        raw_parts.append(f"=== ETHAINTER (rc={rc_e}) ===\n{e_out}\n")

        if rc_e != 0:
            print("[!] ethainter failed / ethainter-bin", flush=True)
            write_triplet(
                output_dir,
                stem,
                "\n".join(raw_parts),
                {"findings": [], "detected_categories": []},
                {
                    "tool": "ethainter",
                    "contract": str(rel),
                    "contract_stem": stem,
                    "returncode": 9,
                    "detected_categories": [],
                    "num_findings": 0,
                    "elapsed_s": time.time() - t0,
                    "note": "ethainter_bin_fail",
                },
            )
            if args.fail_fast:
                return
            continue

        # mapping
        rel_files = [p for p in out_rel.glob("*") if p.is_file()]
        raw_parts.append(f"=== RELATIONS ===\ncount={len(rel_files)} files={[p.name for p in rel_files][:50]}\n")

        detected = map_relations_to_categories(out_rel)
        payload = normalize_payload(detected)

        meta = {
            "tool": "ethainter",
            "contract": str(rel),
            "contract_stem": stem,
            "returncode": 0,
            "detected_categories": payload.get("detected_categories", []),
            "num_findings": len(payload.get("findings", [])),
            "elapsed_s": time.time() - t0,
            "note": "ok",
            "chosen_contract": chosen_contract,
            "relations_dir": str(out_rel),
            "relations_count": len(rel_files),
        }
        write_triplet(output_dir, stem, "\n".join(raw_parts), payload, meta)
        print("[✓] ethainter finished", flush=True)


if __name__ == "__main__":
    main()
