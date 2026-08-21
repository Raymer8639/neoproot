#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
local_prefix=${NEOPROOT_LOCAL_PREFIX:-"$HOME/.local"}

export C_INCLUDE_PATH="$local_prefix/include${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
export CPLUS_INCLUDE_PATH="$local_prefix/include${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}"
export LIBRARY_PATH="$local_prefix/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$local_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

make -C "$repo_root/src" -B neoproot CC="${CC:-clang}" CXX="${CXX:-clang++}"
"$repo_root/src/neoproot" --version | grep -F 'process_vm = yes'
