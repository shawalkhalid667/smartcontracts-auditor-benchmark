# mythril_check_mapping.py

"""
Mapping from Mythril SWC IDs to SmartBugs-Curated categories.

We keep this STRICT:
- Only SWCs we explicitly map are counted as "GT" (ground-truth-relevant).
- Other SWCs are treated as "OOR_SECURITY" (security-ish, but outside our benchmark).
- Non-SWC / weird issues are treated as "NOISE".
"""

# Canonical SmartBugs categories:
#   access_control, arithmetic, bad_randomness, denial_of_service,
#   front_running, other, reentrancy, short_addresses,
#   time_manipulation, unchecked_low_level_calls

SWC_TO_CATEGORY = {
    # --- Arithmetic / integer bugs ---
    "SWC-101": "arithmetic",          # Integer Overflow and Underflow

    # --- Reentrancy ---
    "SWC-107": "reentrancy",          # Reentrancy

    # --- Access control / authorization ---
    "SWC-105": "access_control",      # Unprotected Ether Withdrawal
    "SWC-106": "access_control",      # Unprotected SELFDESTRUCT
    "SWC-108": "access_control",      # State Variable Default Visibility
    "SWC-112": "access_control",      # Delegatecall to Untrusted Callee
    "SWC-115": "access_control",      # Authorization through tx.origin

    # --- Time / randomness / chain-dependent ---
    "SWC-116": "time_manipulation",   # Block values as a proxy for time
    "SWC-120": "bad_randomness",      # Weak Sources of Randomness from Chain Attributes

    # --- Denial of service ---
    "SWC-113": "denial_of_service",   # DoS with failed call
    "SWC-128": "denial_of_service",   # DoS with unexpected revert (rough mapping)

    # --- Unchecked low-level calls ---
    "SWC-104": "unchecked_low_level_calls",  # Unchecked Call Return Value
}


def map_swc_to_category(swc_id: str):
    """
    Return a SmartBugs category for a given SWC id, or None if unmapped.
    """
    if not swc_id:
        return None
    swc_id = swc_id.strip().upper()
    return SWC_TO_CATEGORY.get(swc_id)


def categorize(swc_id: str, title: str = ""):
    """
    Classify a Mythril issue into:
      - ("GT", <smartbugs_category>)      -> used in precision/recall scoring
      - ("OOR_SECURITY", <swc_id>)        -> security issue but outside our GT categories
      - ("NOISE", None)                   -> informational / unparsable / non-SWC

    We treat any SWC-* issue that is not explicitly mapped as OOR_SECURITY.
    Everything else is NOISE.
    """
    swc_id = (swc_id or "").strip()

    # 1) Strict mapping to SmartBugs categories
    cat = map_swc_to_category(swc_id)
    if cat is not None:
        return "GT", cat

    # 2) Security-ish but outside our taxonomy: still SWC-coded
    if swc_id.upper().startswith("SWC-"):
        return "OOR_SECURITY", swc_id.upper()

    # 3) Everything else (style, info, weird tooling issues) → noise
    return "NOISE", None
