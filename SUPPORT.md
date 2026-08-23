# Support

## Where to ask

- Use [GitHub Discussions](https://github.com/Raymer8639/neoproot/discussions)
  for usage questions, rootfs setup, and ideas.
- Use [GitHub Issues](https://github.com/Raymer8639/neoproot/issues) for
  reproducible defects and concrete feature requests.
- Use the private process in [SECURITY.md](SECURITY.md) for vulnerabilities.

Include the neoproot version, host OS, ARM64 device or CPU, rootfs, full command
line, and a minimal reproduction. Remove tokens, private paths, personal data,
and proprietary rootfs files before posting.

## Support boundaries

neoproot is a community-maintained ARM64 project. Best-effort help is available
for supported ARM64 Linux and native Termux builds; x86_64, other CPU
architectures, and published glibc assets on Termux are out of scope.

Maintainers cannot provide support for obtaining or redistributing rootfs
images, bypassing host or application restrictions, privileged Android setup,
or data recovery. neoproot uses ptrace emulation and is not a kernel-level
security boundary; do not rely on it to isolate untrusted users or rootfses.

## Response expectations

This is a volunteer project. There is no response-time or compatibility
guarantee. Clear, minimal reproductions receive the best chance of a useful
response.
