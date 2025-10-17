# KLEE toolchain with LLVM/Clang 13 from apt.llvm.org (no LLVM build)
FROM ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC LANG=C.UTF-8

# Base system and build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget gnupg xz-utils unzip file \
    build-essential ninja-build cmake pkg-config \
    python3 python3-pip python3-setuptools python3-venv \
    z3 libz3-dev lsb-release libncurses5-dev \
    libcap-dev software-properties-common git zlib1g-dev libsqlite3-dev \
    libboost-program-options-dev libboost-filesystem-dev libboost-system-dev \
    flex bison texinfo \
    && rm -rf /var/lib/apt/lists/*

# Install LLVM/Clang 13 from apt.llvm.org
WORKDIR /tmp
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 13 && rm -f llvm.sh

# Select LLVM/Clang 13
ENV CC=clang-13 CXX=clang++-13 \
    LLVM_CONFIG=llvm-config-13 \
    LLVM_COMPILER=clang \
    PATH="/usr/lib/llvm-13/bin:${PATH}"

# Python tools (lit, wllvm/extract-bc)
RUN python3 -m pip install --no-cache-dir lit wllvm

RUN apt-get update && apt-get install -y software-properties-common \
    && add-apt-repository ppa:ubuntu-toolchain-r/test -y \
    && apt-get update && apt-get install -y gcc-10 g++-10 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 100

RUN apt-get update && apt-get install -y wget gpg \
    && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null \
       | gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main" \
       > /etc/apt/sources.list.d/kitware.list \
    && apt-get update \
    && apt-get install -y cmake \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Install prefix
ENV APP_PREFIX=/app
RUN mkdir -p ${APP_PREFIX}
ENV PATH="${APP_PREFIX}/bin:${APP_PREFIX}/sbin:${PATH}"

# Build klee-uclibc (x86_64 premade config exists; aarch64 not supported)
WORKDIR /tmp
RUN git clone --depth=1 https://github.com/klee/klee-uclibc.git
WORKDIR /tmp/klee-uclibc
RUN ./configure --make-llvm-lib --with-cc=${CC} --with-llvm-config=${LLVM_CONFIG} \
 && make -j"$(nproc)" \
 && mkdir -p ${APP_PREFIX}/klee-uclibc \
 && cp -a lib include ${APP_PREFIX}/klee-uclibc/ \
 && rm -rf /tmp/klee-uclibc
ENV KLEE_UCLIBC="${APP_PREFIX}/klee-uclibc"

# Copy local KLEE source (assumes ./klee next to this Dockerfile)
WORKDIR /src
COPY klee/ /src/klee/

# Configure, build, install KLEE (assertions OFF to match distro LLVM)
WORKDIR /src/klee/build
RUN cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=${APP_PREFIX} \
    -DLLVM_CONFIG_BINARY=${LLVM_CONFIG} \
    -DENABLE_ASSERTIONS=OFF \
    -DENABLE_POSIX_RUNTIME=ON \
    -DENABLE_KLEE_UCLIBC=ON \
    -DKLEE_UCLIBC_PATH=${KLEE_UCLIBC} \
    -DENABLE_SOLVER_Z3=ON \
    -DENABLE_UNIT_TESTS=OFF \
    -DENABLE_TCMALLOC=OFF \
    .. \
 && ninja -j"$(nproc)" \
 && ninja install \
 && rm -rf /src/klee

# Helpful env
ENV KLEE_RUNTIME_BUILD="${APP_PREFIX}/lib/klee/runtime" \
    KLEE_INCLUDE_PATH="${APP_PREFIX}/include/klee"

RUN pip3 install tabulate gcovr
RUN apt update && apt install gdb -y

WORKDIR /work
