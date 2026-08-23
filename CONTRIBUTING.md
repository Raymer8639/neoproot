# Contributing to neoproot

Thanks for improving neoproot. This project targets ARM64 Linux and Android
Termux; x86_64 is not a supported build or runtime target.

## Before opening an issue

Search existing issues and read [SUPPORT.md](SUPPORT.md). Security-sensitive
reports belong in the private process described by [SECURITY.md](SECURITY.md),
not in a public issue.

## Development setup

Build and test on a native ARM64 Linux host with the same commands used by CI:

```sh
sudo apt-get update
sudo apt-get install clang llvm lld libtalloc-dev pkg-config upx binutils
make -C src neoproot CC=clang CXX=clang++
cd tests
make -s all
sh test-build-script.sh
sh test-process-vm-build.sh
sh test-runtime-bindings.sh
PROOT=../src/neoproot sh basic_test.sh
PROOT=../src/neoproot sh advanced_test.sh
PROOT=../src/neoproot sh test-security-regressions.sh
PROOT=../src/neoproot sh test-link2symlink-dirent.sh
PROOT=../src/neoproot sh test-bwrap-oldroot-bind.sh
PROOT=../src/neoproot sh test-bwrap-proc-dirfd.sh
PROOT=../src/neoproot sh test-tracer-guard.sh
```

For the portable ARMv8-A build, use:

```sh
make -C src -B neoproot CC=clang CXX=clang++ \
  MARCH="-march=armv8-a -mtune=generic"
```

On Termux, install `clang make llvm binutils pkg-config talloc` and use `sh build.sh`.
The published release assets are built on Ubuntu ARM64; a native Termux build
is the compatibility fallback when a release asset does not run on a device.

## Pull requests

- Start from the current default branch and keep each PR focused.
- Describe the user-visible problem, the approach, and the ARM64 environment
  used for testing.
- Add or update a regression test for a behavior change or bug fix when
  practical.
- Run the relevant commands above before requesting review.
- Do not include generated binaries, build products, unrelated formatting, or
  private rootfs contents in a PR.
- Preserve the project's C23/C++23 and existing formatting conventions.

Maintainers may request a reduced reproduction, additional traces with secrets
removed, or a split of unrelated changes. By contributing, you agree that your
contribution is licensed under the repository's [GPLv2 license](COPYING).
