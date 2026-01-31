# slither_check_mapping.py

"""
Mapping from Slither detectors to:
  - SmartBugs vulnerability categories (used for TP/FP/FN)
  - Out-of-scope security-relevant findings (OOR_SECURITY)
  - Noise / non-security warnings (OOR_NOISE)
"""

# ============================
# SMARTBUGS CATEGORY MAPPING
# ============================

SLITHER_TO_CATEGORY = {
    # ---- ACCESS CONTROL ----
    "arbitrary-send-eth": "access_control",
    "controlled-delegatecall": "access_control",
    "incorrect-modifier": "access_control",
    "tx-origin": "access_control",

    # ---- ARITHMETIC ----
    "divide-before-multiply": "arithmetic",
    "events-maths": "arithmetic",

    # ---- BAD RANDOMNESS ----
    "weak-prng": "bad_randomness",

    # ---- DENIAL OF SERVICE ----
    "locked-ether": "denial_of_service",
    "return-bomb": "denial_of_service",
    "calls-loop": "denial_of_service",

    # ---- REENTRANCY ----
    "reentrancy-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",

    # ---- TIME MANIPULATION ----
    "timestamp": "time_manipulation",

    # ---- UNCHECKED LOW LEVEL CALLS ----
    "unchecked-send": "unchecked_low_level_calls",
    "unchecked-transfer": "unchecked_low_level_calls",
    "unchecked-lowlevel": "unchecked_low_level_calls",
}

# ============================
# SECURITY-RELEVANT BUT OUT-OF-SCOPE DETECTORS
# (kept for qualitative analysis; NOT used in TP/FP/FN)
# ============================

SECURITY_RELATED_UNMAPPED = {
    # You can expand this list as you inspect Slither output.
    "missing-zero-address-check",
    "controlled-state-variable",
    "dangerous-low-level",
}

# ============================
# NOISE / STYLE / NON-SECURITY DETECTORS
# (ignored for evaluation)
# ============================

NOISE_DETECTORS = {
    "naming-convention",
    "shadowing-state",
    "unused-state-variable",
    "unused-function",
    "solc-version",
    "pragma-experimental",
    "dead-code",
    "too-many-state-variables",
    "too-many-lines",
}


def categorize(raw_type: str):
    """
    Classify a Slither detector name into:
      - ("GT", smartbugs_category)       -> included in TP/FP/FN
      - ("OOR_SECURITY", raw_type)       -> security-related but not in SmartBugs taxonomy
      - ("OOR_NOISE", raw_type)          -> style / compiler / non-security noise
    """
    if raw_type in SLITHER_TO_CATEGORY:
        return "GT", SLITHER_TO_CATEGORY[raw_type]

    if raw_type in SECURITY_RELATED_UNMAPPED:
        return "OOR_SECURITY", raw_type

    if raw_type in NOISE_DETECTORS:
        return "OOR_NOISE", raw_type

    # By default, treat unknown detectors as noise for now.
    # You can later promote specific names into SECURITY_RELATED_UNMAPPED.
    return "OOR_NOISE", raw_type
