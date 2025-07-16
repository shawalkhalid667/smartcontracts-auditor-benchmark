FROM nvidia/cuda:12.1.1-cudnn8-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-dev \
    git \
    tar \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY datasets /app/datasets
COPY prompts /app/prompts
COPY scripts /app/scripts
COPY tools /app/tools

# Upgrade pip and install PyTorch separately with CUDA support
RUN pip3 install --upgrade pip && \
    pip3 install torch==2.2.2 --index-url https://download.pytorch.org/whl/cu121

# Then install the rest normally from PyPI
RUN pip3 install \
    unsloth==2025.7.3 \
    einops \
    xformers \
    bitsandbytes \
    peft



CMD ["bash"]

