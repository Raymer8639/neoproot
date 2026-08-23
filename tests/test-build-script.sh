#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work_root=$(mktemp -d "$repo_root/.neoproot-build-script.XXXXXX")
tools="$work_root/tools"
project="$work_root/project"
trace="$work_root/trace"

cleanup() {
    rm -rf "$work_root"
}
trap cleanup EXIT INT TERM

mkdir -p "$tools" "$project/src" "$trace"
cp "$repo_root/build.sh" "$project/build.sh"
chmod 755 "$project/build.sh"

write_tool() {
    name=$1
    shift
    printf '%s\n' '#!/bin/sh' "$@" > "$tools/$name"
    chmod 755 "$tools/$name"
}

write_tool uname 'printf "%s\\n" aarch64'
write_tool clang 'exit 0'
write_tool llvm-config 'exit 0'
write_tool as 'exit 0'
write_tool ld.bfd 'exit 0'
write_tool pkg-config 'exit 0'
write_tool make 'printf "%s\\n" new > src/neoproot' 'chmod 755 src/neoproot'
write_tool cp 'printf "%s\\n" "$*" >> "$NEOPROOT_TEST_TRACE/cp"' 'exec /bin/cp "$@"'
write_tool mv 'printf "%s\\n" "$*" >> "$NEOPROOT_TEST_TRACE/mv"' 'exec /bin/mv "$@"'

run_build() {
    (
        cd "$project"
        PATH="$tools:$PATH" NEOPROOT_TEST_TRACE="$trace" "$@"
    )
}

set +e
invalid_output=$(run_build sh ./build.sh unexpected 2>&1)
invalid_status=$?
set -e
test "$invalid_status" -eq 2
printf '%s\n' "$invalid_output" | grep -F 'Usage: sh build.sh [install]' >/dev/null

set +e
prefix_output=$(run_build env -u PREFIX sh ./build.sh install 2>&1)
prefix_status=$?
set -e
test "$prefix_status" -eq 2
printf '%s\n' "$prefix_output" | grep -F 'PREFIX' >/dev/null

prefix="$work_root/prefix"
mkdir -p "$prefix/bin"
printf '%s\n' old > "$prefix/bin/neoproot"
run_build env PREFIX="$prefix" sh ./build.sh install
test "$(cat "$prefix/bin/neoproot")" = new
test ! -e "$prefix/bin/.neoproot-install"
test ! -e "$prefix/bin/.neoproot-install.tmp"
test ! -e "$prefix/bin/neoproot.tmp"
test "$(sed -n '1p' "$trace/cp")" != "src/neoproot $prefix/bin/neoproot"
test "$(sed -n '1p' "$trace/mv")" != ""

printf '%s\n' 'build script tests passed'
