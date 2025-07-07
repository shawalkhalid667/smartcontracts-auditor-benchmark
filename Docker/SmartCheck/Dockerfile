FROM ubuntu:20.04

# Avoid interactive tzdata prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y curl openjdk-8-jdk gnupg ca-certificates && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set Java 8 as default
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Install SmartCheck
RUN npm install -g @smartdec/smartcheck

# Create working dir
WORKDIR /app

ENTRYPOINT ["smartcheck"]
