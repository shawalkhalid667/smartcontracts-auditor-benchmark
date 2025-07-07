FROM nvidia/cuda:12.1.1-cudnn8-devel-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3-pip python3-dev git curl \
    && rm -rf /var/lib/apt/lists/*

# Symlink python3 to python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Upgrade pip
RUN python3 -m pip install --upgrade pip

# Install torch w/ CUDA 12.1 (CPU fallback logic is in Python)
RUN pip install -Uq torch==2.2.2+cu121 torchvision==0.17.2+cu121 --index-url https://download.pytorch.org/whl/cu121

# Transformers (gemma support)
RUN pip install -Uq transformers==4.40.1

# Bitsandbytes compiled for CUDA 12.1
RUN pip install -Uq bitsandbytes==0.43.1 --prefer-binary

# Additional deps (lower ones override)
RUN pip install -Uq \
    bitsandbytes==0.42.0 \
    peft==0.8.2 \
    trl==0.7.10 \
    accelerate==0.27.1 \
    datasets==2.17.0 \
    wandb \
    "numpy<2"

# Avoid crashing if GPU not available
ENV PYTORCH_ENABLE_MPS_FALLBACK=1
ENV TRANSFORMERS_NO_ADVISORY_WARNINGS=1

# Copy code into image
WORKDIR /app
COPY . /app
COPY programs /programs

CMD ["python3"]
