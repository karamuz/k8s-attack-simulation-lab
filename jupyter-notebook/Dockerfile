FROM jupyter/base-notebook

USER root

RUN apt-get update && \
    apt-get install -y curl vim net-tools iputils-ping util-linux procps && \
    curl -LO https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl && \
    chmod +x kubectl && mv kubectl /usr/local/bin/kubectl

ENTRYPOINT ["bash"]