FROM ubuntu:18.04
LABEL maintainer="Hyperledger <hyperledger-indy@lists.hyperledger.org>"

# very common packages
RUN apt-get update && apt-get dist-upgrade -y && apt-get install -y \
    git \
    wget \
    vim \
    apt-transport-https \
    ca-certificates \
    apt-utils \
    python3.5 \
    python3-pip \
    python-setuptools

# pypi based packages
RUN pip3 install -U \
    'pip<10.0.0' \
    setuptools \
    virtualenv

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys CE7709D068DB5E88 && \
    echo "deb https://repo.sovrin.org/deb xenial master" >> /etc/apt/sources.list && \
    apt-get update

RUN echo "deb https://repo.sovrin.org/sdk/deb xenial master" >> /etc/apt/sources.list && \
    apt-get update

# set highest priority for indy sdk packages in core repo
COPY indy-core-repo.preferences /etc/apt/preferences.d/indy-core-repo

RUN apt-get update -y && apt-get install -y \
    python3-nacl \
    libindy-crypto=0.4.5 \
    libindy=1.13.0~1420 \
    libbz2-dev \
    zlib1g-dev \
    liblz4-dev \
    libsnappy-dev \
    rocksdb=5.8.8

