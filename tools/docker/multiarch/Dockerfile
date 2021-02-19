ARG BASE_IMAGE=debian:10.7-slim
FROM ${BASE_IMAGE} AS base

ENV LANG=en_US.UTF-8

ARG TARGETARCH
ARG GOSU_VERSION=1.12
ARG GOSU_SHA256

ENV HOST_USER_ID=9001

COPY versions_${TARGETARCH}.sh /opt/versions.sh
COPY entrypoint.sh /docker-entrypoint.sh

RUN set -xe; \
    . /opt/versions.sh; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes --no-install-recommends make gcc g++ ca-certificates curl locales; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    # Setup locale
    echo $LANG UTF-8 > /etc/locale.gen; \
    locale-gen; \
    update-locale LANG=$LANG

RUN set -xe; \
    . /opt/versions.sh; \
    # Setup gosu
    curl -o /usr/local/bin/gosu -sSL https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${TARGETARCH}; \
    echo "${GOSU_SHA256}  /usr/local/bin/gosu" | sha256sum -c -; \
    chmod +x /usr/local/bin/gosu; \
    # Setup entrypoint
    chmod +x /docker-entrypoint.sh

WORKDIR /work

ENTRYPOINT ["/docker-entrypoint.sh"]

FROM base AS builder
ARG TARGETARCH

ARG CMAKE_VERSION=3.19.5
ARG CMAKE_SHA256
ARG RUSTUP_INIT_VERSION=1.23.1
ARG RUSTUP_INIT_SHA256
ARG RUST_VERSION=1.49.0
ARG ERLANG_VERSION=23.2.1-1~debian~buster
ARG ERLANG_SHA256
ARG ELIXIR_VERSION=1.11.2-1~debian~buster
ARG ELIXIR_SHA256
ARG JDK_SHA256
ARG JDK_VERSION="2020-10-23-08-51"



ENV CMAKE_HOME=/opt/cmake \
    RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/usr/rust/cargo \
    JAVA_HOME=/opt/java/openjdk

COPY emulator.sh /opt/emulators/${TARGETARCH}-linux-gnu.sh
COPY toolchain.cmake.${TARGETARCH} /opt/toolchains/${TARGETARCH}-linux-gnu.cmake

RUN set -xe; \
    # Setup cmake
    . /opt/versions.sh; \
    ln -s /opt/toolchains/${TARGETARCH}-linux-gnu.cmake /opt/toolchains/detected_target.cmake; \
    CMAKE_PACKAGE="cmake-${CMAKE_VERSION}-Linux-${ALT_ARCH_NAME}.tar.gz"; \
    curl -sSOL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${CMAKE_PACKAGE}"; \
    echo "${CMAKE_SHA256}  ${CMAKE_PACKAGE}" | sha256sum -c -; \
    tar -xf "${CMAKE_PACKAGE}" -C /opt/; \
    mv "/opt/cmake-${CMAKE_VERSION}-Linux-${ALT_ARCH_NAME}" "${CMAKE_HOME}"; \
    rm -rf "${CMAKE_PACKAGE}"

RUN set -xe; \
    # Setup rust
    . /opt/versions.sh; \
    curl -sSOL \
    "https://static.rust-lang.org/rustup/archive/${RUSTUP_INIT_VERSION}/${ALT_ARCH_NAME}-unknown-linux-gnu/rustup-init"; \
    echo "${RUSTUP_INIT_SHA256}  rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal \
    --default-toolchain "$RUST_VERSION" --default-host ${ALT_ARCH_NAME}-unknown-linux-gnu; \
    rm rustup-init; \
    chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"; \
    PATH="${RUSTUP_HOME}/bin:${CARGO_HOME}/bin:$PATH"; \
    rustup component add rustfmt; \
    rustup component add clippy; \
    rustup toolchain install nightly-x86_64-unknown-linux-gnu; \
    rustup component add rustfmt --toolchain nightly-x86_64-unknown-linux-gnu; \
    rustup component add clippy --toolchain nightly-x86_64-unknown-linux-gnu;

RUN set -xe; \
    # Setup erlang
    . /opt/versions.sh; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes --no-install-recommends \
    libncurses5 libwxbase3.0-0v5 libwxgtk3.0-gtk3-0v5 libsctp1 procps; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    ERLANG_PACKAGE="esl-erlang_${ERLANG_VERSION}_${TARGETARCH}.deb"; \
    curl -sSOL "https://packages.erlang-solutions.com/erlang/debian/pool/${ERLANG_PACKAGE}"; \
    echo "${ERLANG_SHA256}  ${ERLANG_PACKAGE}" | sha256sum -c -; \
    dpkg -i "${ERLANG_PACKAGE}"; \
    rm -rf "${ERLANG_PACKAGE}"; \
    # Setup elixir
    ELIXIR_PACKAGE="elixir_${ELIXIR_VERSION}_all.deb"; \
    curl -sSOL "https://packages.erlang-solutions.com/erlang/debian/pool/${ELIXIR_PACKAGE}"; \
    echo "${ELIXIR_SHA256}  ${ELIXIR_PACKAGE}" | sha256sum -c; \
    dpkg -i "${ELIXIR_PACKAGE}"; \
    rm -rf "${ELIXIR_PACKAGE}"; \
    mix local.hex --force && mix local.rebar --force

RUN set -xe; \
    # Setup JDK
    . /opt/versions.sh; \
    cd /tmp; \
    JAVA_PACKAGE="OpenJDK11U-jdk_${JDK_ARCH_NAME}_linux_hotspot_${JDK_VERSION}.tar.gz"; \
    curl -sSOL \
    "https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk11u-${JDK_VERSION}/${JAVA_PACKAGE}"; \
    echo "  ${JAVA_PACKAGE}"; \
    mv "${JAVA_PACKAGE}" openjdk.tar.gz; \
    mkdir -p "${JAVA_HOME}"; \
    cd "${JAVA_HOME}"; \
    tar -xf /tmp/openjdk.tar.gz --strip-components=1; \
    rm -rf /tmp/openjdk.tar.gz


ENV PATH="${JAVA_HOME}/bin:${RUSTUP_HOME}/bin:${CARGO_HOME}/bin:${CMAKE_HOME}/bin:$PATH" \
    AR=/usr/bin/ar \
    AS=/usr/bin/as \
    CC=/usr/local/bin/gcc \
    CPP=/usr/local/bin/cpp \
    CXX=/usr/local/bin/g++