#!/bin/bash
#SBATCH --job-name=sc_sh_forge
#SBATCH --output=logs/sc_sh_forge_%j.out
#SBATCH --error=logs/sc_sh_forge_%j.err
#SBATCH --time=02:00:00
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --partition=normal_q    # adjust to your Tinkercliff partition

set -e
cd "$SLURM_SUBMIT_DIR"
mkdir -p logs

source mythril_env/bin/activate

echo "--- SmartCheck on FORGE ---"
python tools/smartcheck_runner.py \
    --contracts-dir dataset/forge_benchmark/contracts \
    --output-dir    results/smartcheck_forge \
    --gt            dataset/forge_benchmark/vulnerabilities.json \
    --evaluate

echo "--- Solhint on FORGE ---"
python tools/solhint_runner.py \
    --contracts-dir dataset/forge_benchmark/contracts \
    --output-dir    results/solhint_forge \
    --gt            dataset/forge_benchmark/vulnerabilities.json \
    --evaluate

echo "=== sc_sh_forge DONE ==="
