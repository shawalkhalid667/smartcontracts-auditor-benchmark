#!/usr/bin/env python3
"""
smartllama_runner.py

Runs Smart-LLaMA-DPO (local HF model) on SmartBugs-Curated-like dataset and evaluates against vulnerabilities.json,
using the SAME tool-agnostic metrics schema as smartcheck_runner.py / mythril_runner.py / slither_runner.py.

Per contract outputs:
- results/smartllama/<stem>.raw.txt        (always; prompt + model output + errors)
- results/smartllama/<stem>.json           (always; parsed JSON OR fallback inferred categories)
- results/smartllama/<stem>.meta.json      (always; tool-agnostic metadata)

Evaluation (--evaluate):
- results/smartllama/evaluation_common.csv
- results/smartllama/evaluation_primary_by_category.csv
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
    return stem[len(cat) + 1 :]


def extract_first_json_object(text: str) -> Optional[str]:
    """
    Extract the first balanced top-level JSON object from text using brace matching.
    Much safer than "first { / last }".
    """
    if not text:
        return None

    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_str = False
    esc = False

    for i in range(start, len(text)):
        ch = text[i]

        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue

        if ch == '"':
            in_str = True
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        return candidate
                except Exception:
                    return None

    return None


def infer_categories_from_text(text: str) -> Set[str]:
    """
    Fallback when model refuses to output JSON.
    Conservative keyword matching to still produce detected_categories for evaluation.
    """
    t = (text or "").lower()
    cats: Set[str] = set()

    # reentrancy
    if "reentranc" in t:
        cats.add("reentrancy")

    # front running
    if "front run" in t or "frontrun" in t or "front-run" in t:
        cats.add("front_running")

    # denial of service
    if "denial of service" in t or re.search(r"\bdos\b", t):
        cats.add("denial_of_service")

    # randomness (avoid over-triggering, but keep simple)
    if "bad randomness" in t or "rng" in t or "blockhash" in t or ("random" in t and "pseudo" in t):
        cats.add("bad_randomness")

    # time manipulation
    if "block.timestamp" in t or "timestamp dependency" in t or "time manipulation" in t:
        cats.add("time_manipulation")

    # access control
    if "access control" in t or "onlyowner" in t or "authorization" in t or "unauthorized" in t:
        cats.add("access_control")

    # short addresses
    if "short address" in t:
        cats.add("short_addresses")

    # arithmetic
    if "overflow" in t or "underflow" in t or "integer overflow" in t or "arithmetic" in t:
        cats.add("arithmetic")

    # unchecked low-level calls
    if (
        ("unchecked" in t and "call" in t)
        or ("low-level call" in t)
        or (".call.value" in t)
        or ("address.call" in t)
    ):
        cats.add("unchecked_low_level_calls")

    # if it claims vulnerability/security but none matched
    if not cats and ("vulnerab" in t or "attack" in t or "exploit" in t or "security" in t):
        cats.add("other")

    return cats


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


def write_triplet(output_dir: Path, stem: str, raw_text: str, payload: dict, meta: dict) -> None:
    """
    Ensures we always write raw/json/meta (same invariant as other runners).
    """
    (output_dir / f"{stem}.raw.txt").write_text(raw_text, encoding="utf-8", errors="ignore")
    (output_dir / f"{stem}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8", errors="ignore")
    (output_dir / f"{stem}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8", errors="ignore")


def scan_meta_counts(contracts_dir: Path, output_dir: Path) -> Tuple[int, int, int, int, int]:
    """
    Returns:
      contracts_total, contracts_success, contracts_crash, contracts_empty, contracts_missing_output
    Success/empty/crash are based on meta.json when present.
    Missing_output = contracts for which no <stem>.json exists.
    """
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


# ---------------- Prompting ----------------
SYSTEM_INSTRUCTIONS = """You are a smart contract security auditor.

CRITICAL OUTPUT RULES:
- Output MUST be exactly ONE valid JSON object and NOTHING ELSE.
- The first character MUST be '{' and the last character MUST be '}'.
- Do NOT output prose, markdown, numbering, code fences, or extra commentary.

Task: Identify which SmartBugs vulnerability categories are present in the contract.

Allowed categories (use these exact strings):
unchecked_low_level_calls, time_manipulation, bad_randomness, denial_of_service, front_running,
access_control, short_addresses, reentrancy, arithmetic, other

Output JSON schema (exact keys):
{
  "findings": [
    {
      "category": "<one of the allowed categories>",
      "severity": <int 1..5>,
      "confidence": <int 1..3>,
      "title": "<short>",
      "rationale": "<1-3 sentences>"
    }
  ],
  "detected_categories": ["..."]
}

Rules:
- If you are not confident, omit the finding (prefer precision).
- If you find nothing, output {"findings": [], "detected_categories": []}.
- Do not include any text outside the JSON object.
"""


def build_prompt(contract_path: Path, contract_source: str, max_chars: int) -> str:
    """
    Returns USER content only. System instructions are passed separately (via chat template if supported).
    This significantly improves JSON compliance vs. embedding "### System" inside the user prompt.
    """
    src = contract_source
    if max_chars and len(src) > max_chars:
        head = src[: max_chars // 2]
        tail = src[-max_chars // 2 :]
        src = head + "\n\n/* ... truncated ... */\n\n" + tail

    return (
        "Return ONLY the JSON object described in the system message.\n"
        f"CONTRACT_FILE: {contract_path.name}\n"
        "SOLIDITY_SOURCE_BEGIN\n"
        f"{src}\n"
        "SOLIDITY_SOURCE_END\n"
    )


# ---------------- Model Inference ----------------
def load_model(model_path: str, device: str, dtype_str: str, tokenizer_path: str = ""):
    if torch is None:
        raise RuntimeError("torch/transformers not available in this environment.")

    if dtype_str.lower() in {"bf16", "bfloat16"}:
        dtype = torch.bfloat16
    elif dtype_str.lower() in {"fp16", "float16"}:
        dtype = torch.float16
    else:
        dtype = torch.float32

    tok_src = tokenizer_path if tokenizer_path else model_path

    tok = AutoTokenizer.from_pretrained(tok_src, use_fast=True, trust_remote_code=True)
    if tok.pad_token_id is None and tok.eos_token_id is not None:
        tok.pad_token_id = tok.eos_token_id

    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=dtype,
        device_map="auto" if device == "auto" else None,
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )
    if device != "auto":
        model = model.to(device)

    model.eval()
    return tok, model


def generate_json(tokenizer, model, system_text: str, user_text: str, max_new_tokens: int) -> str:
    """
    Prefer tokenizer chat template when available (LLaMA-family instruction following improves a lot).
    Decodes only newly generated tokens (no prompt echo).
    """
    dev = next(model.parameters()).device

    messages = [
        {"role": "system", "content": system_text.strip()},
        {"role": "user", "content": user_text.strip()},
    ]

    if hasattr(tokenizer, "apply_chat_template"):
        input_ids = tokenizer.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
        ).to(dev)
    else:
        # Fallback: simple concatenation if chat template is unavailable
        prompt = system_text.strip() + "\n\n" + user_text.strip()
        toks = tokenizer(prompt, return_tensors="pt")
        input_ids = toks["input_ids"].to(dev)

    input_len = input_ids.shape[-1]

    with torch.no_grad():
        out = model.generate(
            input_ids=input_ids,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    gen_ids = out[0][input_len:]
    text = tokenizer.decode(gen_ids, skip_special_tokens=True)
    return text.strip()


def normalize_payload(obj: dict) -> dict:
    """
    Keep schema stable and safe:
    - findings validated
    - detected_categories = validated union(findings categories, obj.detected_categories)
    """
    findings = obj.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    clean_findings: List[dict] = []
    det_cats: Set[str] = set()

    declared = obj.get("detected_categories", [])
    if isinstance(declared, list):
        for c in declared:
            if c in SMARTBUGS_CATEGORIES:
                det_cats.add(c)

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

    return {"findings": clean_findings, "detected_categories": sorted(det_cats)}


def categories_topk(findings: List[dict], k: int) -> Set[str]:
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
    ap.add_argument("--evaluate", action="store_true")
    ap.add_argument("--clean", action="store_true")

    ap.add_argument("--model-path", default="", help="Local HF model path (required unless only --evaluate)")
    ap.add_argument("--tokenizer-path", default="", help="Tokenizer path (use base_wo_mu if needed)")
    ap.add_argument("--device", default="auto", help="auto|cpu|cuda (auto recommended)")
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

    contracts = sorted(contracts_dir.rglob("*.sol"))
    print(f"Found {len(contracts)} .sol files under {contracts_dir}")

    # If running (not evaluate), load model once
    if not args.evaluate:
        if not args.model_path:
            raise ValueError("--model-path is required unless using --evaluate only.")
        tok, model = load_model(args.model_path, args.device, args.dtype, args.tokenizer_path)
    else:
        tok = None
        model = None

    success = 0
    empty = 0
    crash = 0

    for i, c in enumerate(contracts, 1):
        stem = c.stem
        rel = c.relative_to(contracts_dir)
        print(f"\n[{i}/{len(contracts)}] Evaluating {rel}...")

        if args.evaluate:
            continue

        # read source
        try:
            src = c.read_text(errors="ignore")
        except Exception as e:
            crash += 1
            raw = f"ERROR reading file: {type(e).__name__}: {e}\n"
            payload = {"findings": [], "detected_categories": []}
            meta = {
                "tool": "smartllama",
                "contract": str(rel),
                "contract_stem": stem,
                "returncode": 3,
                "detected_categories": [],
                "num_findings": 0,
                "elapsed_s": 0.0,
                "note": "read_error",
            }
            write_triplet(output_dir, stem, raw, payload, meta)
            print("[!] SmartLLaMA failed / read_error")
            continue

        user_text = build_prompt(c, src, args.max_chars)

        t0 = time.time()
        err_msg = ""
        model_out = ""

        try:
            model_out = generate_json(tok, model, SYSTEM_INSTRUCTIONS, user_text, args.max_new_tokens)
        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}"

        dt = time.time() - t0

        raw = (
            "=== SYSTEM ===\n"
            + SYSTEM_INSTRUCTIONS
            + "\n\n=== USER ===\n"
            + user_text
            + "\n\n=== MODEL_OUTPUT ===\n"
            + (model_out or "")
            + "\n\n=== ERROR ===\n"
            + (err_msg or "")
            + f"\n\n=== ELAPSED_S ===\n{dt:.4f}\n"
        )

        if err_msg:
            crash += 1
            payload = {"findings": [], "detected_categories": []}
            meta = {
                "tool": "smartllama",
                "contract": str(rel),
                "contract_stem": stem,
                "returncode": 1,
                "detected_categories": [],
                "num_findings": 0,
                "elapsed_s": dt,
                "note": "runtime_exception",
            }
            write_triplet(output_dir, stem, raw, payload, meta)
            (output_dir / f"{stem}.error.txt").write_text(err_msg[:20000], encoding="utf-8", errors="ignore")
            print("[!] SmartLLaMA failed / runtime_exception")
            continue

        json_text = extract_first_json_object(model_out)

        # ---------- MINIMAL CHANGE: better fallback for P@K, same categories ----------
        if json_text is None:
            inferred = infer_categories_from_text(model_out)
            cats_sorted = sorted(inferred)
            findings = [
                {
                    "category": c_cat,
                    "severity": 1,
                    "confidence": 1,
                    "title": c_cat,
                    "rationale": "Category inferred from SmartLLaMA free-form explanation text.",
                }
                for c_cat in cats_sorted
            ]
            payload = {"findings": findings, "detected_categories": cats_sorted}
            meta = {
                "tool": "smartllama",
                "contract": str(rel),
                "contract_stem": stem,
                "returncode": 0,
                "detected_categories": payload.get("detected_categories", []),
                "num_findings": len(findings),
                "elapsed_s": dt,
                "note": "fallback_text_parse_no_json",
            }
            write_triplet(output_dir, stem, raw, payload, meta)
            (output_dir / f"{stem}.error.txt").write_text((model_out or "")[:20000], encoding="utf-8", errors="ignore")

            if payload["detected_categories"]:
                success += 1
            else:
                empty += 1

            print("[i] SmartLLaMA free-form output (fallback categories inferred from text)")
            continue
        # ---------------------------------------------------------------------------

        try:
            obj = json.loads(json_text)
            if not isinstance(obj, dict):
                raise ValueError("JSON is not an object")
        except Exception:
            crash += 1
            payload = {"findings": [], "detected_categories": []}
            meta = {
                "tool": "smartllama",
                "contract": str(rel),
                "contract_stem": stem,
                "returncode": 2,
                "detected_categories": [],
                "num_findings": 0,
                "elapsed_s": dt,
                "note": "json_parse_error",
            }
            write_triplet(output_dir, stem, raw, payload, meta)
            (output_dir / f"{stem}.error.txt").write_text((model_out or "")[:20000], encoding="utf-8", errors="ignore")
            print("[!] SmartLLaMA failed / JSON parse error")
            continue

        payload = normalize_payload(obj)
        if payload.get("detected_categories"):
            success += 1
        else:
            empty += 1

        meta = {
            "tool": "smartllama",
            "contract": str(rel),
            "contract_stem": stem,
            "returncode": 0,
            "detected_categories": payload.get("detected_categories", []),
            "num_findings": len(payload.get("findings", [])),
            "elapsed_s": dt,
            "note": "model_json",
        }
        write_triplet(output_dir, stem, raw, payload, meta)

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

    contracts_total, success_count, crash_count, empty_count, missing_output_count = scan_meta_counts(
        contracts_dir, output_dir
    )

    scored, missing_out, micro, prf_at_k = compute_micro_and_topk(gt, output_dir, supported_set=None)
    scored_s, missing_out_s, micro_s, prf_at_k_s = compute_micro_and_topk(gt, output_dir, supported_set=SUPPORTED_CATEGORIES)
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
        print(f"Supported P@{kk}:{m.precision:.2f} R:{m.recall:.2f} F1:{m.f1:.2f}")

    print("\n=== SmartLLaMA Per-Category Recall (Primary Label) ===")
    for cat in SMARTBUGS_CATEGORIES:
        s = by_cat[cat]
        print(f"{cat} Total:{s['total']} Correct:{s['correct']} Missed:{s['missed']} Error:{s['error']} Recall:{s['recall']:.2f}")

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
