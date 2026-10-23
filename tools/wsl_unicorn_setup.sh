#!/bin/bash
# dev-time helper (WSL): fetch unicorn into a user-space prefix without sudo,
# then configure + build the Linux test set with g++-13.
set -e
PREFIX="$HOME/unicorn-root"
mkdir -p "$HOME/synth-pkgs"
cd "$HOME/synth-pkgs"
apt download libunicorn-dev
apt download libunicorn2
for d in *.deb; do
  dpkg -x "$d" "$PREFIX/"
done
echo "-- unicorn files in prefix:"
find "$PREFIX" -name 'unicorn*' | head -8
echo "-- configure:"
cd /mnt/c/devdrv/src/sheller
cmake -B "$HOME/build-sheller" -S . -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=g++-13 \
  -DCMAKE_C_COMPILER=gcc-13 \
  -DCMAKE_PREFIX_PATH="$PREFIX"
echo "-- build engine + tests:"
cmake --build "$HOME/build-sheller" --target synth_modules_test loader_pe_e2e_test -j"$(nproc)"
echo "-- done"
