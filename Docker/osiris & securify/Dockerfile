# securify - osiris joint dockerfile
FROM ubuntu:18.04

ARG SOLC=0.4.22
SHELL ["/bin/bash", "-c"]

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    GOPATH=/root/go \
    PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install base packages and locales
RUN apt-get update && apt-get install -y \
    software-properties-common \
    locales \
    wget \
    gdebi \
    curl \
    unzip \
    sudo \
    tar \
    pandoc \
    python3.7 \
    python3-pip \
    python3-dev \
    dos2unix \
    # python recommended the below one too
    python3.7-dev \
    build-essential \
    git \
    virtualenv \
    graphviz \
    python3-setuptools \
    python3-wheel \
    libffi-dev

RUN locale-gen en_US.UTF-8

# Install Soufflé
RUN wget https://github.com/souffle-lang/souffle/releases/download/1.6.2/souffle_1.6.2-1_amd64.deb -O /tmp/souffle.deb && \
    gdebi --n /tmp/souffle.deb && rm /tmp/souffle.deb

# Install Z3 (prebuilt binary)
RUN wget https://github.com/Z3Prover/z3/releases/download/z3-4.6.0/z3-4.6.0-x64-ubuntu-16.04.zip && \
    unzip z3-4.6.0-x64-ubuntu-16.04.zip && \
    mv z3-4.6.0-x64-ubuntu-16.04/bin/* /usr/local/bin && \
    rm -rf z3-4.6.0-x64-ubuntu-16.04*

# Install Go
RUN wget https://storage.googleapis.com/golang/go1.9.2.linux-amd64.tar.gz && \
    tar -xvzf go1.9.2.linux-amd64.tar.gz && \
    mv go /usr/local && \
    rm go1.9.2.linux-amd64.tar.gz && \
    mkdir -p $GOPATH

# Install Geth
RUN wget https://github.com/ethereum/go-ethereum/archive/v1.8.3.zip && \
    unzip v1.8.3.zip && \
    cd go-ethereum-1.8.3 && make all && mv build/bin/* /usr/local/bin && cd .. && rm -rf go-ethereum-1.8.3*

# Install Solidity 0.4.21 (built from source)
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.21/solidity_0.4.21.tar.gz && \
    tar -xvzf solidity_0.4.21.tar.gz && \
    cd solidity_0.4.21 && ./scripts/install_deps.sh && ./scripts/build.sh && cp build/solc/solc /usr/local/bin/solc-0.4.21 && cd .. && rm -rf solidity_0.4.21*

# Install solc 0.4.19 for Osiris
RUN curl -L https://github.com/ethereum/solidity/releases/download/v0.4.19/solc-static-linux > /usr/bin/solc-0.4.19 && \
    chmod +x /usr/bin/solc-0.4.19

# Install solc 0.5.12 for Securify
RUN curl -L https://github.com/ethereum/solidity/releases/download/v0.5.12/solc-static-linux > /usr/bin/solc-0.5.12 && \
    chmod +x /usr/bin/solc-0.5.12

# Set 0.4.19 as default for Osiris
RUN ln -sf /usr/bin/solc-0.4.19 /usr/local/bin/solc



# Upgrade pip, setup venv
RUN python3.7 -m pip install --upgrade pip setuptools wheel

# Install Python deps
COPY requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

# Install extra packages used by securify
RUN pip3 install requests web3==0.1.9

# Set up securify
WORKDIR /sec
COPY . /sec
ENV PYTHONPATH=/sec

RUN python3.7 setup.py install
RUN cd /sec/securify/staticanalysis/libfunctors && \
    dos2unix compile_functors.sh && \
    chmod +x compile_functors.sh && \
    ./compile_functors.sh


RUN cd /sec/securify/staticanalysis/souffle_analysis && \
    souffle --dl-program=../dl-program \
    --fact-dir=/sec/securify/staticanalysis/facts_in \
    --output-dir=/sec/securify/staticanalysis/facts_out \
    -L../libfunctors -w analysis.dl

ENV LD_LIBRARY_PATH=/sec/securify/staticanalysis/libfunctors

# Copy additional tools (like osiris)
COPY osiris /root/osiris
COPY datasets /root/datasets
COPY testsO /root/testsO
# UNCLEAR IF THESE THREE LINES BELOW WILL CAUSE AN ISSUE
COPY securify /root/securify
COPY setup.py /root/setup.py
COPY solidity.bnf /root/solidity.bnf

# Run a test (optional — remove if not needed)
RUN cd /sec/securify/ && securify staticanalysis/testContract.sol || true

ENTRYPOINT ["python3.7", "securify/__main__.py"]
