#!/bin/bash
#SBATCH --job-name=static_sb_rerun
#SBATCH --output=logs/static_sb_rerun_%j.out
#SBATCH --error=logs/static_sb_rerun_%j.err
#SBATCH --time=36:00:00          # Mythril is the bottleneck (~5 min/contract × 143 ≈ 12 h)
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --partition=normal_q    # adjust to your Tinkercliff partition
#SBATCH --account=smart_contract

# ============================================================
# Re-run all static tools on SmartBugs Curated.
# Use --clean to overwrite previous outputs.
# Addresses reviewer concern about scores differing from
# Durieux et al. 2020 / LightCross — lets you report fresh
# numbers from an identical environment.
# ============================================================

set -e
cd "$SLURM_SUBMIT_DIR"
mkdir -p logs

source mythril_env/bin/activate

# SmartBugs curated needs older solc (0.4.x / 0.5.x)
for v in 0.4.0 0.4.2 0.4.9 0.4.10 0.4.11 0.4.13 0.4.15 0.4.16 \
          0.4.18 0.4.19 0.4.21 0.4.22 0.4.23 0.4.24 0.4.25 0.5.0; do
    solc-select install "$v" 2>/dev/null || true
done

CONTRACTS="dataset/smartbugs_curated"
VERSIONS="dataset/versions"
GT="dataset/smartbugs-curated/vulnerabilities.json"

echo "--- Slither (SmartBugs rerun) ---"
python tools/slither_runner.py \
    --contracts-dir "$CONTRACTS" \
    --versions-dir  "$VERSIONS" \
    --output-dir    results/slither_rerun \
    --gt            "$GT" \
    --evaluate

echo "--- SmartCheck (SmartBugs rerun) ---"
python tools/smartcheck_runner.py \
    --contracts-dir "$CONTRACTS" \
    --output-dir    results/smartcheck_rerun \
    --gt            "$GT" \
    --evaluate

echo "--- Solhint (SmartBugs rerun) ---"
python tools/solhint_runner.py \
    --contracts-dir "$CONTRACTS" \
    --output-dir    results/solhint_rerun \
    --gt            "$GT" \
    --evaluate

echo "--- Mythril (SmartBugs rerun — slowest, ~12 h) ---"
python tools/mythril_runner.py \
    --contracts-dir "$CONTRACTS" \
    --versions-dir  "$VERSIONS" \
    --output-dir    results/mythril_rerun \
    --gt            "$GT" \
    --evaluate

echo "=== static_sb_rerun DONE ==="
