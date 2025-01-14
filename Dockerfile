#
# Copyright (c) 2022, Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#  * Neither the name of Intel Corporation nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

FROM debian:12 AS gramine

# Install Gramine dependencies
RUN env DEBIAN_FRONTEND=noninteractive apt-get update && \
    env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        autoconf bison build-essential cmake coreutils curl gawk git \
        libprotobuf-c-dev linux-headers-generic nasm ninja-build \
        pkg-config protobuf-c-compiler protobuf-compiler python3 \
        python3-cryptography python3-protobuf wget meson python3-tomli \
        python3-tomli-w wget gnupg

# COPY ./intel-sgx-deb.key /
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' \
    > /etc/apt/sources.list.d/intel-sgx.list \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -

RUN env DEBIAN_FRONTEND=noninteractive apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y libsgx-dcap-quote-verify-dev

# Install Gramine
RUN git clone https://github.com/gramineproject/gramine.git /gramine

RUN cd /gramine \
    && git fetch origin master \
    && git checkout master \
    && git checkout 115ffeeb72e13a2a6cab9b11160109f171832c60
        
        
RUN mkdir -p /gramine/driver/asm \
    && cd /gramine/driver/asm \
    && wget --timeout=10 -O sgx.h \
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/arch/x86/include/uapi/asm/sgx.h?h=v5.11 \
    && sha256sum sgx.h | grep -q a34a997ade42b61376b1c5d3d50f839fd28f2253fa047cb9c0e68a1b00477956


RUN cd /gramine \
    && meson setup build/ --prefix="/gramine/meson_build_output" \
        --buildtype=release \
        -Ddirect=enabled -Dsgx=enabled \
        \
        \
        -Dsgx_driver=upstream -Dsgx_driver_include_path=/gramine/driver \
        \
    && ninja -C build \
    && ninja -C build install


FROM node:lts-slim AS qvl-builder

ENV DEBIAN_FRONTEND=noninteractive
# install QVL dependencies
RUN apt-get update \
 && apt-get upgrade --assume-yes -o Dpkg::Options::="--force-confold" \
 && apt-get install --assume-yes --no-install-recommends ca-certificates=\* build-essential=\* cmake=\* \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# build OpenSSL FIPS provider (Latest FIPS validated version as of writing is 3.0.8)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# hadolint ignore=SC2086,DL3003
RUN apt-get update \
 && apt-get install --assume-yes --no-install-recommends wget=\* \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
 && wget --progress=dot:giga https://github.com/openssl/openssl/releases/download/openssl-3.0.8/openssl-3.0.8.tar.gz -O /tmp/openssl.tar.gz \
 && echo "6c13d2bf38fdf31eac3ce2a347073673f5d63263398f1f69d0df4a41253e4b3e /tmp/openssl.tar.gz" | sha256sum --check \
 && mkdir /tmp/openssl && cd /tmp/openssl \
 && tar -xzf /tmp/openssl.tar.gz --strip-components=1 -C /tmp/openssl \
 && ./Configure enable-fips && make -j${nproc} \
 && mkdir /tmp/fips && cp /tmp/openssl/providers/fips.so /tmp/fips && cp /tmp/openssl/providers/fipsmodule.cnf /tmp/fips \
 && rm -rf /tmp/openssl.tar.gz /tmp/openssl

 # copy QVL sources
COPY build/qvls /qvl
# build and test QVL
WORKDIR /qvl
RUN ./runUT -DBUILD_LOGS=ON

FROM node:lts-slim AS qvs-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get upgrade --assume-yes -o Dpkg::Options::="--force-confold" \
 && apt-get install --assume-yes --no-install-recommends ca-certificates=\* build-essential=\* cmake=\* \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* 
 
COPY --from=qvl-builder --chown=node:node /qvl /qvl
# copy QVS source files
COPY src /qvs/src
COPY configuration-default /qvs/configuration-default

# Add gramine from gramine stage
COPY --from=gramine --chown=node:node /gramine/meson_build_output /gramine/meson_build_output

# build QVS
RUN echo 'cmake_QVL_PATH=/qvl/Build/Release/dist' >> /qvs/src/.npmrc # workaround for npm 9+ https://github.com/npm/cli/issues/5852
WORKDIR /qvs/src
RUN npm install npm@latest && npm install
# Adoid Intel CA Error
RUN npm config set strict-ssl=false
# copy compiled bianries
RUN mkdir -p /qvs/native/lib/ \
 && cp /qvl/Build/Release/dist/lib/*.so /qvs/native/lib/ \
 && cp /qvs/src/qvl/cmake-build-release/Release/*.node /qvs/native/ \
 && rm -rf /qvs/src/qvl/cmake-build-release
# copy QVS test files
COPY test /qvs/test
# test QVS
WORKDIR /qvs/test
RUN npm install && NODE_ENV=production npm test

FROM node:lts-slim

LABEL description="Quote Verification Service"

# Remove Node package managers and its dependencies and clear apt cache
RUN rm -rf /usr/local/lib/node_modules/ \
    && rm -rf /usr/local/bin/npm \
    && rm -rf /usr/local/bin/npx \
    && rm -rf /opt \
    && rm -rf /var/cache/apt/archives

# Update the OS and install required dependencies
RUN apt-get update && \
    apt-get install -y binutils && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade --assume-yes -o Dpkg::Options::="--force-confold" && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add QVS files from builder
COPY --from=qvs-builder --chown=node:node qvs/native /QVS/native
COPY --from=qvs-builder --chown=node:node qvs/configuration-default/config.yml /QVS/configuration-default/config.yml
COPY --from=qvs-builder --chown=node:node qvs/src /QVS/src
COPY --from=qvl-builder --chown=node:node tmp/fips /QVS/src/fips

# Add gramine from gramine stage
COPY --from=gramine --chown=node:node /gramine/meson_build_output /gramine/meson_build_output
# Include Meson build output directory in $PATH
ENV PATH="/gramine/meson_build_output/bin:$PATH"

# For QVS (my modification)
COPY --chown=node:node configuration-default/certificates /QVS/configuration-default/certificates
# genCSR (communicating to secret_prov sample)
COPY --chown=node:node ra-tls-secret-prov/ssl/ca.crt /QVS/configuration-default/certificates/internal_ca
ENV QVS_SERVICE_CERT_FILE=certificates/qvs-cert.pem \
    QVS_SERVICE_KEY_FILE=certificates/qvs-key.pem \
    QVS_SERVICE_TLS_SERVER_TYPE=TLS \
    QVS_VCS_CLIENT_HOST=localhost \
    QVS_VCS_CLIENT_PORT=8797 \
    QVS_VCS_CLIENT_CERT_FILE=certificates/qvs-to-sss-client-cert.pem \
    QVS_VCS_CLIENT_KEY_FILE=certificates/qvs-to-sss-client-key.pem \
    QVS_ATTESTATION_REPORT_SIGNING_CERTIFICATE=SIGNING_KEY_CERTIFCATE_URL_ENCODED \
    QVS_VCS_CLIENT_SERVERNAME=localhost \
    QVS_DELEGATING_ATTESTATION_CERT_FILE=/QVS/configuration-default/certificates/internal_ca/ca.crt \
    QVS_CACHE_MAX_KEYS=-1

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/QVS/native/lib:/gramine/meson_build_output/lib/x86_64-linux-gnu \
    NODE_ENV=production
    # OPENSSL_CONF=/QVS/src/fips/openssl.cnf \
    # OPENSSL_MODULES=/QVS/src/fips
USER node
ENTRYPOINT ["nodejs", "/QVS/src/bootstrap.js"]
WORKDIR "/QVS"
