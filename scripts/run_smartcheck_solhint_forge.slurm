#!/bin/bash
#SBATCH --job-name=sc_sh_forge
#SBATCH --output=logs/sc_sh_forge_%j.out
#SBATCH --error=logs/sc_sh_forge_%j.err
#SBATCH --time=02:00:00
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --partition=normal_q
#SBATCH --account=smart_contract

set -e
cd "$SLURM_SUBMIT_DIR"
mkdir -p logs

# ── Python environment ────────────────────────────────────────────────────────
source mythril_env/bin/activate

# ── Node.js ───────────────────────────────────────────────────────────────────
module load nodejs/22.17.1-GCCcore-14.3.0

echo "=== Preflight: Node.js / npm ==="
which node && node --version
which npm  && npm  --version
which npx  && npx  --version

# ── Install SmartCheck locally in the job workspace ───────────────────────────
# Using --prefix keeps it out of $HOME and avoids permission issues.
# The binary ends up at node_modules/.bin/smartcheck
SC_PREFIX="$SLURM_SUBMIT_DIR/node_modules_smartcheck"
echo "=== Installing SmartCheck into $SC_PREFIX ==="
npm install --prefix "$SC_PREFIX" smartcheck
SC_BIN="$SC_PREFIX/node_modules/.bin/smartcheck"

echo "=== Preflight: SmartCheck ==="
if [ ! -x "$SC_BIN" ]; then
    echo "ERROR: SmartCheck binary not found at $SC_BIN after npm install."
    echo "SmartCheck will be marked UNSUPPORTED — skipping SmartCheck run."
    SC_AVAILABLE=false
else
    echo "SmartCheck binary: $SC_BIN"
    "$SC_BIN" --version 2>/dev/null || true   # print version if supported
    SC_AVAILABLE=true
fi

# ── Install Solhint locally ───────────────────────────────────────────────────
SH_PREFIX="$SLURM_SUBMIT_DIR/node_modules_solhint"
echo "=== Installing Solhint into $SH_PREFIX ==="
npm install --prefix "$SH_PREFIX" solhint
SH_BIN="$SH_PREFIX/node_modules/.bin/solhint"

echo "=== Preflight: Solhint ==="
if [ ! -x "$SH_BIN" ]; then
    echo "ERROR: Solhint binary not found at $SH_BIN after npm install."
    SH_AVAILABLE=false
else
    echo "Solhint binary: $SH_BIN"
    "$SH_BIN" --version
    SH_AVAILABLE=true
fi

# ── SmartCheck on FORGE ───────────────────────────────────────────────────────
# Note: SmartCheck was designed for Solidity 0.4.x / 0.5.x and has limited
# support for 0.8.x contracts. The runner will probe the tool and print a
# WARNING if the crash rate exceeds 50%. If so, exclude from paper results.
if [ "$SC_AVAILABLE" = true ]; then
    echo ""
    echo "--- SmartCheck on FORGE ---"
    python tools/smartcheck_runner.py \
        --contracts-dir dataset/forge_benchmark/contracts \
        --output-dir    results/smartcheck_forge \
        --smartcheck-cmd "$SC_BIN" \
        --gt            dataset/forge_benchmark/vulnerabilities.json \
        --evaluate
else
    echo "SKIP: SmartCheck not available."
fi

# ── Solhint on FORGE ─────────────────────────────────────────────────────────
if [ "$SH_AVAILABLE" = true ]; then
    echo ""
    echo "--- Solhint on FORGE ---"
    python tools/solhint_runner.py \
        --contracts-dir dataset/forge_benchmark/contracts \
        --output-dir    results/solhint_forge \
        --solhint-bin   "$SH_BIN" \
        --gt            dataset/forge_benchmark/vulnerabilities.json \
        --evaluate
else
    echo "SKIP: Solhint not available."
fi

echo "=== sc_sh_forge DONE ==="
