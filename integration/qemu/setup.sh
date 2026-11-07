#!/usr/bin/env bash
# Fetch and build the stock OP-TEE QEMU v8 environment
# (TF-A + OP-TEE + U-Boot + Linux + Buildroot + QEMU).
#
# STATUS: these are the standard OP-TEE steps; run on Ubuntu 22.04/24.04.
# First build takes 30-60 min and ~30 GB of disk.
set -euo pipefail
WORK=${WORK:-$HOME/pqboot-qemu}
OPTEE_TAG=${OPTEE_TAG:-4.4.0}   # pick a recent release tag

sudo apt-get update
sudo apt-get install -y adb acpica-tools autoconf automake bc bison build-essential \
  ccache cpio cscope curl device-tree-compiler e2tools expect fastboot flex ftp-upload \
  gdisk git libattr1-dev libcap-ng-dev libfdt-dev libftdi-dev libglib2.0-dev libgmp3-dev \
  libhidapi-dev libmpc-dev libncurses5-dev libpixman-1-dev libslirp-dev libssl-dev \
  libtool libusb-1.0-0-dev make mtools netcat-openbsd ninja-build python3-cryptography \
  python3-pip python3-pyelftools python3-serial python-is-python3 rsync swig unzip \
  uuid-dev wget xdg-utils xterm xz-utils zlib1g-dev repo

mkdir -p "$WORK" && cd "$WORK"
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b "$OPTEE_TAG"
repo sync -j"$(nproc)" --no-clone-bundle
cd build
make -j2 toolchains
make -j"$(nproc)"

echo
echo "Stock build done. Try it before patching anything:"
echo "  cd $WORK/build && make run"
echo "Then follow docs/INTEGRATION.md to add pqboot."
