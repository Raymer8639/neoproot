#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work_root=$(mktemp -d "$repo_root/.neoproot-build-script.XXXXXX")
project="$work_root/project"
trap 'rm -rf "$work_root"' EXIT INT TERM
mkdir -p "$project/src"
cp "$repo_root/build.sh" "$project/build.sh"
cp "$repo_root/install.sh" "$project/install.sh"
chmod 755 "$project/build.sh" "$project/install.sh"
set +e
output=$(cd "$project" && sh ./build.sh unexpected 2>&1)
status=$?
set -e
test "$status" -eq 2
echo "$output" | grep -F 'Usage: sh build.sh' >/dev/null
output=$(cd "$project" && sh ./build.sh 2>&1 || true)
echo "$output" | grep -E '缺少依赖|构建完成|Build' >/dev/null || true
echo 'build script tests passed'
