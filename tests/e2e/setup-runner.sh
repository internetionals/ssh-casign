#!/bin/sh
# Install what the end-to-end suite needs on a Debian-based Rust image
# (docker.io/library/rust:1-bookworm): OpenSSH (sshd, ssh-agent, ssh-keygen),
# jq, Python with cryptography (for the mocks), SoftHSM and OpenSC (PKCS#11).
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  openssh-server openssh-client jq python3 python3-cryptography \
  softhsm2 opensc libssl-dev pkg-config ca-certificates curl >/dev/null
mkdir -p /run/sshd
