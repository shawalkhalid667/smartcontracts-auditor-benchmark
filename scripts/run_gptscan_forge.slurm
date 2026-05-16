#!/bin/bash
#SBATCH --job-name=gptscan_forge
#SBATCH --output=logs/gptscan_forge_%j.out
#SBATCH --error=logs/gptscan_forge_%j.err
#SBATCH --time=06:00:00          # ~1 s/contract × 173 + API latency ≈ 1–3 h
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --partition=normal_q    # adjust to your Tinkercliff partition
#SBATCH --account=smart_contract

# ============================================================
# GPTScan on FORGE — run with SAME provider on SmartBugs too!
# Choose ONE provider block below and comment out the other.
# ============================================================

set -e
cd "$SLURM_SUBMIT_DIR"
mkdir -p logs

source mythril_env/bin/activate

# *** Fill in your OpenAI API key before submitting ***
export OPENAI_API_KEY="sk-..."
PROVIDER="openai"
MODEL="gpt-4o"
OUTDIR="results/gptscan_forge"

# --- Alternative: Anthropic Claude (report as separate LLM tool) ---
# export ANTHROPIC_API_KEY="sk-ant-..."
# PROVIDER="anthropic"
# MODEL="claude-sonnet-4-6"
# OUTDIR="results/claude_auditor_forge"

python tools/gptscan_runner.py \
    --contracts-dir dataset/forge_benchmark/contracts \
    --output-dir    "${OUTDIR}" \
    --provider      "${PROVIDER}" \
    --model         "${MODEL}" \
    --rate-limit-delay 1.0 \
    --gt            dataset/forge_benchmark/vulnerabilities.json \
    --evaluate

echo "=== gptscan_forge DONE (provider=${PROVIDER} model=${MODEL}) ==="
