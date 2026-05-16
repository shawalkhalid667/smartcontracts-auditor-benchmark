#!/bin/bash
#SBATCH --job-name=mythril_forge
#SBATCH --output=logs/mythril_forge_%j.out
#SBATCH --error=logs/mythril_forge_%j.err
#SBATCH --time=24:00:00          # Mythril is slow (~5 min/contract × 173 = ~15 h worst case)
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --partition=normal_q    # adjust to your Tinkercliff partition
#SBATCH --account=smart_contract

set -e
cd "$SLURM_SUBMIT_DIR"
mkdir -p logs

source mythril_env/bin/activate

for v in 0.8.0 0.8.10 0.8.13 0.8.15 0.8.17 0.8.18 0.8.19 \
          0.8.20 0.8.21 0.8.22 0.8.23 0.8.24 0.8.25 0.8.26 \
          0.8.27 0.8.28 0.8.29 0.8.30; do
    solc-select install "$v" 2>/dev/null || true
done

python tools/mythril_runner.py \
    --contracts-dir dataset/forge_benchmark/contracts \
    --versions-dir  dataset/versions \
    --output-dir    results/mythril_forge \
    --gt            dataset/forge_benchmark/vulnerabilities.json \
    --evaluate

echo "=== mythril_forge DONE ==="
