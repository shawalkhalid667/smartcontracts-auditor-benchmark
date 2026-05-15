#!/usr/bin/env python3
"""
smartllama_runner.py

Runs Smart-LLaMA-DPO (local HF model) on SmartBugs-Curated-like dataset and evaluates against vulnerabilities.json,
using the SAME tool-agnostic metrics schema as smartcheck_runner.py / mythril_runner.py / slither_runner.py.

Per contract outputs:
- results/smartllama/<stem>.raw.txt        (always; prompt + model output + errors)
- results/smartllama/<stem>.json           (parsed model JSON; only if parsed)
- results/smartllama/<stem>.meta.json      (tool-agnostic metadata; only if parsed)

Evaluation (--evaluate):
- results/smartllama/evaluation_common.csv
- results/smartllama/evaluation_primary_by_category.csv

Assumptions:
- You have a local directory for the model (base or DPO) that Transformers can load.
- You want contract-level category detection, consistent with your other tools.
"""

import argparse
import csv
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Lazy import so `--evaluate` can run without torch installed in some envs.
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
except Exception:
    torch = None
    AutoModelForCausalLM = None
    AutoTokenizer = None


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

# LLM can theoretically emit all categories
SUPPORTED_CATEGORIES: Set[str] = set(SMARTBUGS_CATEGORIES)


# ---------------- Paths ----------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

CONTRACT_DIR_DEFAULT = (REPO_ROOT / "dataset/smartbugs_curated").resolve()
OUTPUT_DIR_DEFAULT = (REPO_ROOT / "results/smartllama").resolve()
GT_CANDIDATES = [
    REPO_ROOT / "dataset/smartbugs_curated/vulnerabilities.json",
    REPO_ROOT / "dataset/smartbugs-curated/vulnerabilities.json",
]


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


def extract_first_json_object(text: str) -> Optional[str]:
    """
    Extract the first top-level JSON object by finding first '{' and last '}'.
    Same robust approach used in your Mythril runner.
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


def clamp_int(x: Optional[int], lo: int, hi: int, default: int) -> int:
    if x is None:
        return default
    try:
        v = int(x)
        return max(lo, min(hi, v))
    except Exception:
        return default


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
    Index parsed JSON outputs by multiple keys to handle prefix/stem mismatches.
    We index:
      - exact stem
      - stripped category prefix stem (access_control_Foo -> Foo)
    """
    idx: Dict[str, Path] = {}
    for p in output_dir.glob("*.json"):
        if p.name.endswith(".meta.json"):
            continue
        stem = p.stem
        idx[stem] = p
        idx[strip_category_prefix(stem)] = p
    return idx


# ---------------- Prompting ----------------
SYSTEM_INSTRUCTIONS = """You are a smart contract security auditor.
Given a Solidity contract, you MUST output a SINGLE JSON object only (no markdown, no prose).
Your task: identify which SmartBugs vulnerability categories are present in the contract.

Allowed categories (use these exact strings):
unchecked_low_level_calls, time_manipulation, bad_randomness, denial_of_service, front_running,
access_control, short_addresses, reentrancy, arithmetic, other

Output JSON schema (exact keys):
{
  "findings": [
    {
      "category": "<one of the allowed categories>",
      "severity": <int 1..5>,         // 5=critical, 4=high, 3=medium, 2=low, 1=info
      "confidence": <int 1..3>,       // 3=high, 2=medium, 1=low
      "title": "<short>",
      "rationale": "<1-3 sentences>"
    }
  ],
  "detected_categories": ["..."]      // unique categories derived from findings
}

Rules:
- If you are not confident, omit the finding (prefer precision).
- If you find nothing, output {"findings": [], "detected_categories": []}.
"""


def build_prompt(contract_path: Path, contract_source: str, max_chars: int) -> str:
    src = contract_source
    if max_chars and len(src) > max_chars:
        # keep the head and tail; LLMs often need declarations + key logic
        head = src[: max_chars // 2]
        tail = src[-max_chars // 2 :]
        src = head + "\n\n/* ... truncated ... */\n\n" + tail

    return (
        SYSTEM_INSTRUCTIONS
        + "\n\n"
        + f"CONTRACT_FILE: {contract_path.name}\n"
        + "SOLIDITY_SOURCE_BEGIN\n"
        + src
        + "\nSOLIDITY_SOURCE_END\n"
    )


# ---------------- Model Inference ----------------
def load_model(model_path: str, device: str, dtype_str: str, tokenizer_path: str = ""):
    """
    Load model from `model_path` and tokenizer from `tokenizer_path` if provided.
    This fixes the observed issue where the DPO folder may not include SentencePiece/tokenizer files,
    while base_wo_mu does (tokenizer.json, tokenizer_config.json, special_tokens_map.json, etc.).
    """
    if torch is None:
        raise RuntimeError("torch/transformers not available in this environment.")

    if dtype_str.lower() in {"bf16", "bfloat16"}:
        dtype = torch.bfloat16
    elif dtype_str.lower() in {"fp16", "float16"}:
        dtype = torch.float16
    else:
        dtype = torch.float32

    tok_src = tokenizer_path if tokenizer_path else model_path

    # Tokenizer: prefer base_wo_mu (has tokenizer.json) if provided
    tok = AutoTokenizer.from_pretrained(tok_src, use_fast=True, trust_remote_code=True)
    if tok.pad_token_id is None and tok.eos_token_id is not None:
        tok.pad_token_id = tok.eos_token_id

    # Model: load from the model path (DPO or base)
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=dtype,  # transformers warns deprecated arg in some versions; still works
        device_map="auto" if device == "auto" else None,
        trust_remote_code=True,
    )
    if device != "auto":
        model = model.to(device)

    model.eval()
    return tok, model


def generate_json(
    tokenizer,
    model,
    prompt: str,
    max_new_tokens: int,
) -> str:
    # Deterministic by default for benchmarking
    inputs = tokenizer(prompt, return_tensors="pt")
    # move to model device
    dev = next(model.parameters()).device
    inputs = {k: v.to(dev) for k, v in inputs.items()}

    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=None,  # avoid passing unsupported flags in some forks
            top_p=None,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    text = tokenizer.decode(out[0], skip_special_tokens=True)
    # Model output includes the prompt; keep only the tail after prompt to reduce parsing noise
    if text.startswith(prompt):
        return text[len(prompt) :].strip()
    return text.strip()


def normalize_payload(obj: dict) -> dict:
    """
    Enforce schema + sanitize categories.
    """
    findings = obj.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    clean_findings: List[dict] = []
    det_cats: Set[str] = set()

    for f in findings:
        if not isinstance(f, dict):
            continue
        cat = f.get("category")
        if cat not in SMARTBUGS_CATEGORIES:
            continue
        sev = clamp_int(f.get("severity"), 1, 5, 0)
        conf = clamp_int(f.get("confidence"), 1, 3, 0)
        title = (f.get("title") or "").strip()
        rationale = (f.get("rationale") or "").strip()

        clean_findings.append(
            {
                "category": cat,
                "severity": sev,
                "confidence": conf,
                "title": title,
                "rationale": rationale,
            }
        )
        det_cats.add(cat)

    # detected_categories can be user-provided; we override with findings-derived for consistency
    out = {
        "findings": clean_findings,
        "detected_categories": sorted(det_cats),
    }
    return out


def categories_topk(findings: List[dict], k: int) -> Set[str]:
    """
    Rank findings by severity desc, then confidence desc, stable by category/title.
    """
    def key(f: dict):
        sev = int(f.get("severity") or 0)
        conf = int(f.get("confidence") or 0)
        return (sev, conf, f.get("category", ""), f.get("title", ""))

    ordered = sorted(findings, key=key, reverse=True)
    top = ordered[:k]
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


def compute_primary_label_recall_table(
    gt: Dict[str, Set[str]],
    output_dir: Path,
) -> Dict[str, dict]:
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
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--clean", action="store_true")

    # model args
    ap.add_argument("--model-path", default="", help="Local HF model path (required unless only --evaluate)")
    ap.add_argument(
        "--tokenizer-path",
        default="",
        help="Tokenizer path (use base_wo_mu path if DPO model folder lacks tokenizer files)",
    )
    ap.add_argument("--device", default="auto", help='auto|cpu|cuda (auto recommended)')
    ap.add_argument("--dtype", default="bf16", help="bf16|fp16|fp32")
    ap.add_argument("--max-new-tokens", type=int, default=512)
    ap.add_argument("--max-chars", type=int, default=20000, help="truncate Solidity source to this many chars (0=disable)")
    ap.add_argument("--sleep-ms", type=int, default=0, help="optional delay between contracts")

    args = ap.parse_args()

    contracts_dir = Path(args.contracts_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    ensure_dir(output_dir)

    if args.clean:
        for p in output_dir.glob("*"):
            if p.is_file():
                safe_unlink(p)

    # If only evaluating, no need to load model
    if not args.evaluate:
        if not args.model_path:
            raise ValueError("--model-path is required unless using --evaluate only.")
        tok, model = load_model(args.model_path, args.device, args.dtype, args.tokenizer_path)
    else:
        tok = None
        model = None

    contracts = sorted(contracts_dir.rglob("*.sol"))
    print(f"Found {len(contracts)} .sol files under {contracts_dir}")

    success = 0
    empty = 0
    crash = 0

    for i, c in enumerate(contracts, 1):
        stem = c.stem
        rel = c.relative_to(contracts_dir)
        print(f"\n[{i}/{len(contracts)}] Evaluating {rel}...")

        src = ""
        try:
            src = c.read_text(errors="ignore")
        except Exception as e:
            crash += 1
            (output_dir / f"{stem}.raw.txt").write_text(
                f"ERROR reading file: {e}\n",
                encoding="utf-8",
                errors="ignore",
            )
            continue

        if args.evaluate:
            # skip generation when evaluating
            continue

        prompt = build_prompt(c, src, args.max_chars)
        t0 = time.time()
        err_msg = ""
        model_out = ""

        try:
            model_out = generate_json(tok, model, prompt, args.max_new_tokens)
        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}"

        dt = time.time() - t0

        # Always write raw
        (output_dir / f"{stem}.raw.txt").write_text(
            "=== PROMPT ===\n"
            + prompt
            + "\n\n=== MODEL_OUTPUT ===\n"
            + (model_out or "")
            + "\n\n=== ERROR ===\n"
            + (err_msg or "")
            + f"\n\n=== ELAPSED_S ===\n{dt:.4f}\n",
            encoding="utf-8",
            errors="ignore",
        )

        if err_msg:
            crash += 1
            (output_dir / f"{stem}.error.txt").write_text(
                err_msg[:20000],
                encoding="utf-8",
                errors="ignore",
            )
            print("[!] SmartLLaMA crash")
            continue

        json_text = extract_first_json_object(model_out)
        if json_text is None:
            crash += 1
            (output_dir / f"{stem}.error.txt").write_text(
                (model_out or "")[:20000],
                encoding="utf-8",
                errors="ignore",
            )
            print("[!] SmartLLaMA non-JSON output")
            continue

        try:
            obj = json.loads(json_text)
            if not isinstance(obj, dict):
                raise ValueError("JSON is not an object")
        except Exception:
            crash += 1
            (output_dir / f"{stem}.error.txt").write_text(
                (model_out or "")[:20000],
                encoding="utf-8",
                errors="ignore",
            )
            print("[!] SmartLLaMA JSON parse error")
            continue

        payload = normalize_payload(obj)
        findings = payload.get("findings", [])
        if isinstance(findings, list) and len(findings) == 0:
            empty += 1
        else:
            success += 1

        # Write parsed json (for evaluation)
        (output_dir / f"{stem}.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        meta = {
            "tool": "smartllama",
            "contract": str(rel),
            "contract_stem": stem,
            "returncode": 0,
            "detected_categories": payload.get("detected_categories", []),
            "num_findings": len(payload.get("findings", [])),
            "elapsed_s": dt,
        }
        (output_dir / f"{stem}.meta.json").write_text(
            json.dumps(meta, indent=2),
            encoding="utf-8",
            errors="ignore",
        )

        print("[✓] SmartLLaMA parsed JSON")

        if args.sleep_ms:
            time.sleep(args.sleep_ms / 1000.0)

    if not args.evaluate:
        print("\n=== SmartLLaMA Run Summary ===")
        print(f"Success: {success}")
        print(f"Empty:   {empty}")
        print(f"Crash:   {crash}")
        print(f"Outputs: {output_dir}")

    # ---------------- Evaluation ----------------
    if not args.evaluate:
        return

    gt_path = Path(args.gt).resolve() if args.gt else next((p for p in GT_CANDIDATES if p.exists()), Path(""))
    if not gt_path or not gt_path.exists():
        raise FileNotFoundError(
            "Ground truth vulnerabilities.json not found. "
            "Pass --gt /path/to/vulnerabilities.json or place it under dataset/smartbugs_curated/."
        )

    gt = load_smartbugs_annotations(gt_path)

    # Infer run counters from artifacts to keep evaluation consistent even if you evaluate later
    # (We still keep schema identical to your other runners.)
    out_jsons = [p for p in output_dir.glob("*.json") if not p.name.endswith(".meta.json")]
    out_raws = list(output_dir.glob("*.raw.txt"))
    contracts_total = len(list(Path(args.contracts_dir).resolve().rglob("*.sol")))

    # Estimate crash/empty/success from parsed payloads + raw/error files
    # crash ≈ missing parsed JSON but raw exists OR error.txt exists.
    parsed_stems = {p.stem for p in out_jsons}
    all_stems = {p.stem for p in Path(args.contracts_dir).resolve().rglob("*.sol")}
    missing_parsed = sorted(list(all_stems - parsed_stems))

    # Determine empty/success by reading parsed payloads
    empty_count = 0
    success_count = 0
    for p in out_jsons:
        try:
            obj = json.loads(p.read_text(errors="ignore"))
            f = obj.get("findings", [])
            if isinstance(f, list) and len(f) == 0:
                empty_count += 1
            else:
                success_count += 1
        except Exception:
            pass

    crash_count = len(missing_parsed)

    # Overall micro + @K
    scored, missing_out, micro, prf_at_k = compute_micro_and_topk(gt, output_dir, supported_set=None)

    # Coverage-aware micro + @K
    scored_s, missing_out_s, micro_s, prf_at_k_s = compute_micro_and_topk(gt, output_dir, supported_set=SUPPORTED_CATEGORIES)

    # Primary-label per-category recall
    by_cat = compute_primary_label_recall_table(gt, output_dir)

    print("\n=== SmartLLaMA Evaluation (Category Labels) ===")
    print(f"Contracts scored: {scored}")
    print(f"Contracts missing output: {missing_out}")
    print(f"Micro-TP:{micro.tp} FP:{micro.fp} FN:{micro.fn}  P:{micro.precision:.2f} R:{micro.recall:.2f} F1:{micro.f1:.2f}")
    for kk in K_LIST:
        m = prf_at_k[kk]
        print(f"P@{kk}:{m.precision:.2f} R@{kk}:{m.recall:.2f} F1@{kk}:{m.f1:.2f}")

    print("\n=== SmartLLaMA Coverage-Aware (Supported Only) ===")
    print(f"Supported categories: {sorted(SUPPORTED_CATEGORIES)}")
    print(f"Contracts scored: {scored_s}")
    print(f"Contracts missing output: {missing_out_s}")
    print(f"Micro-TP:{micro_s.tp} FP:{micro_s.fp} FN:{micro_s.fn}  P:{micro_s.precision:.2f} R:{micro_s.recall:.2f} F1:{micro_s.f1:.2f}")
    for kk in K_LIST:
        m = prf_at_k_s[kk]
        print(f"Supported P@{kk}:{m.precision:.2f} R@{kk}:{m.recall:.2f} F1@{kk}:{m.f1:.2f}")

    print("\n=== SmartLLaMA Per-Category Recall (Primary Label) ===")
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
        "tool": "smartllama",
        "contracts_total": contracts_total,
        "contracts_success": success_count,
        "contracts_crash": crash_count,
        "contracts_empty": empty_count,
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
            w.writerow(["smartllama", cat, s["total"], s["correct"], s["missed"], s["error"], f"{s['recall']:.6f}"])

    print(f"\nWrote: {out_csv}")
    print(f"Wrote: {out_primary}")


if __name__ == "__main__":
    main()
