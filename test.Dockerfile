ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y build-essential libseccomp2 libseccomp-dev rake pkg-config git

RUN groupadd -r -g 593 lrun && \
    useradd --uid 1000 --gid lrun --shell /bin/bash -m judger
