FROM ubuntu:16.04
LABEL maintainer="Hyperledger <hyperledger-indy@lists.hyperledger.org>"

RUN apt-get update && apt-get dist-upgrade -y

# very common packages
RUN apt-get install -y \
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

RUN echo "#!/bin/bash\n\
set -e\n\
set -x\n\
apt-get -y autoremove\n\
rm -rf /var/lib/apt/lists/*" >>/usr/local/bin/indy_image_clean
RUN chmod 755 /usr/local/bin/indy_image_clean

RUN indy_image_clean

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys CE7709D068DB5E88 && \
    echo "deb https://repo.sovrin.org/deb xenial master" >> /etc/apt/sources.list && \
    apt-get update

RUN indy_image_clean

RUN echo "deb https://repo.sovrin.org/sdk/deb xenial master" >> /etc/apt/sources.list && \
    apt-get update

RUN echo "Package: /indy-crypto/ /libindy/\n\
Pin: release l=Indy Main Repository\n\
Pin-Priority: 1000" >> /etc/apt/preferences.d/indy-core-repo

RUN apt-get update -y && apt-get install -y \
    python3-nacl \
    libindy-crypto=0.4.5 \
    libindy=1.13.0~1420 \
# rocksdb python wrapper
    libbz2-dev \
    zlib1g-dev \
    liblz4-dev \
    libsnappy-dev \
    rocksdb=5.8.8 \
    ursa=0.3.2-2 \
    jq

RUN indy_image_clean
