#!/bin/bash

NPROC_PER_NODE=8
NNODES=1
RANK=0
MASTER_ADDR=127.0.0.1
MASTER_PORT=29500

cd ../LLaMA-Factory
CUDA_VISIBLE_DEVICES=0,1,2,3,4,5,6,7 torchrun \
    --nproc_per_node $NPROC_PER_NODE \
    --nnodes $NNODES \
    --node_rank $RANK \
    --master_addr $MASTER_ADDR \
    --master_port $MASTER_PORT \
    src/train.py ../SFT/llama3.1_full_cpt_8b_smart_llama_mix_general.yaml