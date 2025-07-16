#!/bin/bash

TOOL=$1
GPU=$2
CONTRACT=${3:-$TOOL}
PROMPT=${4:-$TOOL}

# Choose the script name based on GPU flag
if [ "$GPU" == "1" ]; then
    SCRIPT="run_GPU.py"
else
    SCRIPT="run.py"
fi

case "$TOOL" in
    FTSA_Llama)
        echo "Running $TOOL on $CONTRACT with $SCRIPT"
        python3 ../tools/FTSA_Llama/$SCRIPT "test.txt" "$PROMPT.txt"
        ;;
    Smart_Llama)
        echo "Running $TOOL on $CONTRACT with $SCRIPT"
        python3 ../tools/Smart_Llama/$SCRIPT "test2.txt" "$PROMPT.txt"
        ;;
    FTSA_Gemma)
        echo "Running $TOOL on $CONTRACT with $SCRIPT"
        python3 ../tools/FTSA_Gemma/$SCRIPT "$CONTRACT.txt" "$PROMPT.txt"
        ;;
    *)
        echo "Unknown tool: $TOOL"
        ;;
esac
