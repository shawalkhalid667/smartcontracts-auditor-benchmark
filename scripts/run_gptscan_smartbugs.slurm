#!/bin/bash
#SBATCH --job-name=gptscan_sb
#SBATCH --output=logs/gptscan_sb_%j.out
#SBATCH --error=logs/gptscan_sb_%j.err
#SBATCH --time=04:00:00          # 143 contracts × ~1 s + API latency ≈ 1–2 h
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --partition=normal_q    # adjust to your Tinkercliff partition

# ============================================================
# GPTScan on SmartBugs Curated — use SAME provider as FORGE!
# ============================================================

set -e
cd "$SLURM_SUBMIT_DIR"
mkdir -p logs

source mythril_env/bin/activate

# --- OPTION A: OpenAI GPT-4o ---
# export OPENAI_API_KEY="sk-..."
# PROVIDER="openai"
# MODEL="gpt-4o"
# OUTDIR="results/gptscan"

# --- OPTION B: Anthropic Claude ---
# export ANTHROPIC_API_KEY="sk-ant-..."
# PROVIDER="anthropic"
# MODEL="claude-sonnet-4-6"
# OUTDIR="results/claude_auditor"

python tools/gptscan_runner.py \
    --contracts-dir dataset/smartbugs_curated \
    --output-dir    "${OUTDIR}" \
    --provider      "${PROVIDER}" \
    --model         "${MODEL}" \
    --rate-limit-delay 1.0 \
    --gt            dataset/smartbugs-curated/vulnerabilities.json \
    --evaluate

echo "=== gptscan_smartbugs DONE (provider=${PROVIDER}) ==="
