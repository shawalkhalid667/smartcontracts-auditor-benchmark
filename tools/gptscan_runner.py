#!/usr/bin/env python3
"""
gptscan_runner.py

GPTScan-style LLM-based smart contract vulnerability scanner.
Supports OpenAI (GPT-4o) and Anthropic (Claude) as backends via --provider.
Implements the scenario-based vulnerability detection approach from:
  "GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining
   GPT with Program Analysis" (ICSE 2024, Sun et al.)

For a fair paper comparison, use the SAME provider+model on both datasets.

Usage — OpenAI (GPTScan, faithful to ICSE 2024):
  export OPENAI_API_KEY=sk-...
  python tools/gptscan_runner.py \
      --contracts-dir dataset/smartbugs_curated \
      --output-dir results/gptscan \
      --provider openai --model gpt-4o \
      --evaluate --gt dataset/smartbugs_curated/vulnerabilities.json

  python tools/gptscan_runner.py \
      --contracts-dir dataset/forge_benchmark/contracts \
      --output-dir results/gptscan_forge \
      --provider openai --model gpt-4o \
      --evaluate --gt dataset/forge_benchmark/vulnerabilities.json

Usage — Anthropic (Claude-based auditor, report separately):
  export ANTHROPIC_API_KEY=sk-ant-...
  python tools/gptscan_runner.py \
      --contracts-dir dataset/smartbugs_curated \
      --output-dir results/claude_auditor \
      --provider anthropic --model claude-sonnet-4-6 \
      --evaluate --gt dataset/smartbugs_curated/vulnerabilities.json

Requirements:
  pip install openai anthropic
"""

import argparse
import csv
import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    import anthropic as anthropic_sdk
except ImportError:
    anthropic_sdk = None


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
SUPPORTED_CATEGORIES: Set[str] = set(SMARTBUGS_CATEGORIES)

# ---------------- Paths ----------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CONTRACT_DIR_DEFAULT = (REPO_ROOT / "dataset/smartbugs_curated").resolve()
OUTPUT_DIR_DEFAULT = (REPO_ROOT / "results/gptscan").resolve()
GT_CANDIDATES = [
    REPO_ROOT / "dataset/smartbugs_curated/vulnerabilities.json",
    REPO_ROOT / "dataset/smartbugs-curated/vulnerabilities.json",
]

# GPTScan-style vulnerability scenario descriptions aligned to SmartBugs taxonomy.
# Each entry primes GPT with the pattern signature for that category.
CATEGORY_SCENARIOS = {
    "reentrancy": (
        "The contract makes an external call to another contract or address, "
        "and the called contract can re-enter the caller before the first execution completes, "
        "potentially draining funds or corrupting state."
    ),
    "access_control": (
        "Functions that should be restricted (e.g., to the owner, admin, or specific roles) "
        "can be called by arbitrary addresses, or use tx.origin for authentication, "
        "allowing unauthorized access or privilege escalation."
    ),
    "arithmetic": (
        "Integer overflow, underflow, or division-by-zero vulnerabilities that cause "
        "incorrect numerical results, especially in token balances, fee calculations, or reward distributions. "
        "Relevant for contracts using Solidity < 0.8 without SafeMath, or unchecked blocks."
    ),
    "unchecked_low_level_calls": (
        "The return value of a low-level call (call, send, delegatecall, staticcall) "
        "is not checked, so failures are silently ignored and the contract state may be inconsistent."
    ),
    "time_manipulation": (
        "The contract uses block.timestamp or block.number as a source of truth for "
        "randomness, locking periods, or deadlines that miners or validators could manipulate."
    ),
    "bad_randomness": (
        "The contract uses predictable on-chain values (block.prevrandao, blockhash, "
        "block.timestamp, msg.sender, etc.) as a randomness source, which can be predicted or "
        "manipulated by miners or front-runners."
    ),
    "denial_of_service": (
        "A DoS vulnerability where an attacker can permanently or temporarily prevent "
        "legitimate users from using the contract, e.g., by causing an unbounded loop, "
        "reverting a critical function, pushing gas costs beyond the block limit, or "
        "locking funds indefinitely."
    ),
    "front_running": (
        "Transaction ordering dependence: an attacker can observe a pending transaction "
        "and submit their own transaction with higher gas to execute first, gaining an "
        "economic advantage (e.g., sandwich attacks, race conditions on approvals)."
    ),
    "short_addresses": (
        "The contract is vulnerable to short address/parameter attacks where a caller "
        "provides fewer bytes than expected for an address argument, causing the EVM to "
        "pad the arguments incorrectly."
    ),
}

SYSTEM_PROMPT = """You are a smart contract security auditor specializing in Solidity vulnerability detection.
Your task is to analyze the provided Solidity smart contract and identify which vulnerability categories from a fixed taxonomy are present.

The vulnerability categories are:
- reentrancy: External call before state update allows re-entrance
- access_control: Missing or incorrect authorization checks
- arithmetic: Integer overflow, underflow, or precision errors
- unchecked_low_level_calls: Return values of low-level calls (call/send/delegatecall) not checked
- time_manipulation: Block timestamp or number used for security-sensitive logic
- bad_randomness: Predictable on-chain randomness sources
- denial_of_service: Functions that can be permanently blocked or made prohibitively expensive
- front_running: Transaction ordering dependence allowing MEV or race conditions
- short_addresses: Short address / parameter padding attack
- other: Significant vulnerability not fitting the above categories

Respond ONLY with a JSON object in this exact format:
{
  "vulnerabilities": [
    {"category": "<category_name>", "confidence": "<high|medium|low>", "reason": "<brief reason>"}
  ]
}

If no vulnerabilities are found, return: {"vulnerabilities": []}
Use only the exact category names listed above."""


def build_user_prompt(src: str, max_chars: int = 12000) -> str:
    if len(src) > max_chars:
        src = src[:max_chars] + "\n\n// [TRUNCATED]"
    return f"Analyze this Solidity smart contract for vulnerabilities:\n\n```solidity\n{src}\n```"


# ---------------- LLM Call (OpenAI or Anthropic) ----------------
def call_llm(client, provider: str, model: str, src: str,
             max_retries: int = 3, retry_delay: float = 5.0) -> Tuple[str, Optional[dict]]:
    """
    Returns (raw_response_text, parsed_json_or_None).
    Dispatches to OpenAI or Anthropic based on provider.
    """
    user_msg = build_user_prompt(src)
    for attempt in range(max_retries):
        try:
            if provider == "anthropic":
                resp = client.messages.create(
                    model=model,
                    max_tokens=1024,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_msg}],
                )
                raw = resp.content[0].text if resp.content else ""
            else:  # openai
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    temperature=0.0,
                    max_tokens=1024,
                )
                raw = resp.choices[0].message.content or ""
            parsed = extract_json_from_response(raw)
            return raw, parsed
        except Exception as e:
            err_str = str(e)
            if attempt < max_retries - 1:
                wait = retry_delay * (2 ** attempt)
                print(f"  [!] {provider} error (attempt {attempt+1}): {err_str[:80]}. Retrying in {wait:.0f}s...")
                time.sleep(wait)
            else:
                return f"ERROR: {err_str}", None
    return "ERROR: max retries exceeded", None


def extract_json_from_response(text: str) -> Optional[dict]:
    """Extract JSON object from GPT response, handling markdown code blocks."""
    # Try to strip markdown fences
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    # Find first { ... } span
    i = text.find("{")
    j = text.rfind("}")
    if i == -1 or j < i:
        return None
    try:
        obj = json.loads(text[i:j+1])
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    return None


# ---------------- Output Parsing ----------------
def parse_vulnerabilities(gptscan_obj: dict) -> List[dict]:
    """Return list of {category, confidence, reason} dicts."""
    vulns = gptscan_obj.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        return []
    result = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cat = str(v.get("category", "")).strip().lower()
        if cat in SMARTBUGS_CATEGORIES:
            result.append({
                "category": cat,
                "confidence": str(v.get("confidence", "medium")).lower(),
                "reason": str(v.get("reason", ""))[:300],
            })
    return result


def extract_detected_categories(gptscan_obj: dict) -> Set[str]:
    return {v["category"] for v in parse_vulnerabilities(gptscan_obj)}


def confidence_rank(v: dict) -> int:
    c = v.get("confidence", "").lower()
    return {"high": 3, "medium": 2, "low": 1}.get(c, 0)


def extract_detected_categories_topk(gptscan_obj: dict, k: int) -> Set[str]:
    vulns = sorted(parse_vulnerabilities(gptscan_obj), key=confidence_rank, reverse=True)
    return {v["category"] for v in vulns[:k]}


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
                for v in (item.get("vulnerabilities") or []):
                    if isinstance(v, dict) and v.get("category"):
                        gt[stem].add(v["category"])
            elif "file" in item:
                stem = Path(item.get("file", "")).stem
                if item.get("category"):
                    gt[stem].add(item["category"])
    return gt


def build_output_index(output_dir: Path) -> Dict[str, Path]:
    idx: Dict[str, Path] = {}
    for p in output_dir.glob("*.json"):
        if p.name.endswith(".meta.json"):
            continue
        stem = p.stem
        idx[stem] = p
        # strip category prefix (for SmartBugs contracts named access_control_Foo)
        for cat in SMARTBUGS_CATEGORIES_SORTED:
            if stem.startswith(cat + "_"):
                idx[stem[len(cat)+1:]] = p
                break
    return idx


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
    return PRF(
        prf.tp + len(gt_labels & pred_labels),
        prf.fp + len(pred_labels - gt_labels),
        prf.fn + len(gt_labels - pred_labels),
    )


def compute_micro_and_topk(
    gt: Dict[str, Set[str]],
    output_dir: Path,
    supported_set: Optional[Set[str]] = None,
) -> Tuple[int, int, PRF, Dict[int, PRF]]:
    idx = build_output_index(output_dir)
    scored, missing = 0, 0
    micro = PRF(0, 0, 0)
    prf_at_k = {k: PRF(0, 0, 0) for k in K_LIST}

    for stem, gt_cats in gt.items():
        out_file = idx.get(stem)
        if out_file is None or not out_file.exists():
            missing += 1
            continue
        try:
            obj = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            missing += 1
            continue

        gt_l = {c for c in gt_cats if c in SMARTBUGS_CATEGORIES}
        pred_l = extract_detected_categories(obj)
        if supported_set:
            gt_l &= supported_set
            pred_l &= supported_set

        scored += 1
        micro = accumulate_micro_prf(gt_l, pred_l, micro)
        for k in K_LIST:
            pk = extract_detected_categories_topk(obj, k)
            if supported_set:
                pk &= supported_set
            prf_at_k[k] = accumulate_micro_prf(gt_l, pk, prf_at_k[k])

    return scored, missing, micro, prf_at_k


def compute_primary_label_recall_table(gt: Dict[str, Set[str]], output_dir: Path) -> Dict[str, dict]:
    idx = build_output_index(output_dir)
    by_cat = defaultdict(lambda: {"total": 0, "correct": 0, "missed": 0, "error": 0})

    for stem, gt_cats in gt.items():
        primary = None
        for cat in SMARTBUGS_CATEGORIES_SORTED:
            if stem.startswith(cat + "_"):
                primary = cat
                break
        if primary is None:
            only = [c for c in gt_cats if c in SMARTBUGS_CATEGORIES]
            if len(only) == 1:
                primary = only[0]
        if primary is None:
            continue

        by_cat[primary]["total"] += 1
        out_file = idx.get(stem)
        if out_file is None or not out_file.exists():
            by_cat[primary]["error"] += 1
            continue
        try:
            obj = json.loads(out_file.read_text(errors="ignore"))
        except Exception:
            by_cat[primary]["error"] += 1
            continue

        if primary in extract_detected_categories(obj):
            by_cat[primary]["correct"] += 1
        else:
            by_cat[primary]["missed"] += 1

    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        denom = s["correct"] + s["missed"]
        s["recall"] = s["correct"] / denom if denom else 0.0

    return by_cat


# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--contracts-dir", default=str(CONTRACT_DIR_DEFAULT))
    ap.add_argument("--output-dir", default=str(OUTPUT_DIR_DEFAULT))
    ap.add_argument("--provider", default="openai", choices=["openai", "anthropic"],
                    help="LLM provider: openai (GPT-4o, faithful to GPTScan paper) or anthropic (Claude)")
    ap.add_argument("--model", default="gpt-4o",
                    help="Model name. OpenAI: gpt-4o / gpt-4o-mini. Anthropic: claude-sonnet-4-6 / claude-opus-4-7")
    ap.add_argument("--api-key", default="", help="API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY env var)")
    ap.add_argument("--rate-limit-delay", type=float, default=1.0, help="Seconds to sleep between API calls")
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--gt", default="", help="Path to vulnerabilities.json")
    ap.add_argument("--skip-existing", action="store_true", default=True,
                    help="Skip contracts that already have .json output (resume-friendly)")
    ap.add_argument("--no-skip-existing", dest="skip_existing", action="store_false")
    args = ap.parse_args()

    # Build client for selected provider
    if args.provider == "anthropic":
        if anthropic_sdk is None:
            print("ERROR: anthropic package not installed. Run: pip install anthropic")
            return
        api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print("ERROR: No Anthropic API key. Set ANTHROPIC_API_KEY or pass --api-key.")
            return
        client = anthropic_sdk.Anthropic(api_key=api_key)
        # Default model for Anthropic if user didn't override
        if args.model == "gpt-4o":
            args.model = "claude-sonnet-4-6"
    else:
        if OpenAI is None:
            print("ERROR: openai package not installed. Run: pip install openai")
            return
        api_key = args.api_key or os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            print("ERROR: No OpenAI API key. Set OPENAI_API_KEY or pass --api-key.")
            return
        client = OpenAI(api_key=api_key)
    contracts_dir = Path(args.contracts_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    contracts = sorted(contracts_dir.rglob("*.sol"))
    print(f"Found {len(contracts)} .sol files in {contracts_dir}")
    print(f"Provider: {args.provider}  Model: {args.model}")

    success = empty = crash = 0

    for i, c in enumerate(contracts, 1):
        stem = c.stem
        rel = c.relative_to(contracts_dir)
        out_json = output_dir / f"{stem}.json"

        if args.skip_existing and out_json.exists():
            print(f"[{i}/{len(contracts)}] SKIP (exists): {rel}")
            # still count as success for summary
            try:
                obj = json.loads(out_json.read_text())
                if extract_detected_categories(obj) or not parse_vulnerabilities(obj):
                    success += 1
                else:
                    empty += 1
            except Exception:
                success += 1
            continue

        print(f"[{i}/{len(contracts)}] {rel}...", end=" ", flush=True)

        try:
            src = c.read_text(errors="ignore")
        except Exception as e:
            print(f"[!] Read error: {e}")
            crash += 1
            continue

        raw, parsed = call_llm(client, args.provider, args.model, src)

        # Always write raw
        (output_dir / f"{stem}.raw.txt").write_text(raw, encoding="utf-8", errors="ignore")

        if parsed is None:
            print("[!] Parse failed")
            crash += 1
            (output_dir / f"{stem}.error.txt").write_text(raw[:5000], encoding="utf-8", errors="ignore")
            continue

        vulns = parse_vulnerabilities(parsed)
        cats = {v["category"] for v in vulns}

        if not cats:
            empty += 1
        else:
            success += 1

        out_json.write_text(json.dumps(parsed, indent=2), encoding="utf-8", errors="ignore")

        meta = {
            "tool": "gptscan",
            "provider": args.provider,
            "model": args.model,
            "contract": str(rel),
            "contract_stem": stem,
            "detected_categories": sorted(cats),
            "vulnerabilities": vulns,
        }
        (output_dir / f"{stem}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8", errors="ignore")

        print(f"[✓] {sorted(cats) or 'empty'}")

        if args.rate_limit_delay > 0:
            time.sleep(args.rate_limit_delay)

    print(f"\n=== GPTScan Run Summary ===")
    print(f"Success: {success}  Empty: {empty}  Crash: {crash}")
    print(f"Outputs: {output_dir}")

    if not args.evaluate:
        return

    gt_path = Path(args.gt).resolve() if args.gt else next((p for p in GT_CANDIDATES if p.exists()), None)
    if not gt_path or not gt_path.exists():
        print("ERROR: GT not found. Pass --gt /path/to/vulnerabilities.json")
        return

    gt = load_smartbugs_annotations(gt_path)
    scored, missing_out, micro, prf_at_k = compute_micro_and_topk(gt, output_dir)
    scored_s, missing_out_s, micro_s, prf_at_k_s = compute_micro_and_topk(gt, output_dir, SUPPORTED_CATEGORIES)
    by_cat = compute_primary_label_recall_table(gt, output_dir)

    print(f"\n=== GPTScan Evaluation ===")
    print(f"Scored: {scored}  Missing: {missing_out}")
    print(f"Micro  TP:{micro.tp} FP:{micro.fp} FN:{micro.fn}  P:{micro.precision:.2f} R:{micro.recall:.2f} F1:{micro.f1:.2f}")
    for k in K_LIST:
        m = prf_at_k[k]
        print(f"P@{k}:{m.precision:.2f} R@{k}:{m.recall:.2f} F1@{k}:{m.f1:.2f}")

    print(f"\n=== Per-Category Recall (Primary Label) ===")
    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        if s["total"]:
            print(f"{cat:<30} Total:{s['total']} Recall:{s['recall']:.2f}")

    # Write CSVs
    out_csv = output_dir / "evaluation_common.csv"
    headers = [
        "tool", "model", "contracts_total", "contracts_success", "contracts_crash", "contracts_empty",
        "contracts_scored", "contracts_missing_output",
        "micro_tp", "micro_fp", "micro_fn", "micro_precision", "micro_recall", "micro_f1",
        "supported_tp", "supported_fp", "supported_fn", "supported_precision", "supported_recall", "supported_f1",
    ]
    for k in K_LIST:
        headers += [f"p_at_{k}", f"r_at_{k}", f"f1_at_{k}"]

    row = {
        "tool": "gptscan", "model": args.model,
        "contracts_total": len(contracts), "contracts_success": success,
        "contracts_crash": crash, "contracts_empty": empty,
        "contracts_scored": scored, "contracts_missing_output": missing_out,
        "micro_tp": micro.tp, "micro_fp": micro.fp, "micro_fn": micro.fn,
        "micro_precision": f"{micro.precision:.6f}", "micro_recall": f"{micro.recall:.6f}", "micro_f1": f"{micro.f1:.6f}",
        "supported_tp": micro_s.tp, "supported_fp": micro_s.fp, "supported_fn": micro_s.fn,
        "supported_precision": f"{micro_s.precision:.6f}", "supported_recall": f"{micro_s.recall:.6f}", "supported_f1": f"{micro_s.f1:.6f}",
    }
    for k in K_LIST:
        m = prf_at_k[k]
        row[f"p_at_{k}"] = f"{m.precision:.6f}"
        row[f"r_at_{k}"] = f"{m.recall:.6f}"
        row[f"f1_at_{k}"] = f"{m.f1:.6f}"

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerow(row)

    out_primary = output_dir / "evaluation_primary_by_category.csv"
    with open(out_primary, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "category", "total", "correct", "missed", "error", "recall"])
        for cat in SMARTBUGS_CATEGORIES:
            s = by_cat[cat]
            w.writerow(["gptscan", cat, s["total"], s["correct"], s["missed"], s["error"], f"{s['recall']:.6f}"])

    print(f"\nWrote: {out_csv}")
    print(f"Wrote: {out_primary}")


if __name__ == "__main__":
    main()
