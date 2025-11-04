FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install a comprehensive set of tools required by the full run.sh script
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat-traditional \
    iproute2 \
    dnsutils \
    python3 \
    python3-pip \
    cron \
    net-tools \
    util-linux \
    coreutils \
    libhwloc15 \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries
RUN pip3 install requests

# Copy the dropper script and make it executable
COPY dropper.sh /dropper.sh
RUN chmod +x /dropper.sh

# The dropper script will be the entrypoint
ENTRYPOINT ["/dropper.sh"]