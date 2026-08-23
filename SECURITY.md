# Security Policy

## Supported versions

Security fixes are currently provided on the `v5.9.x` release line of
neoproot.

## Reporting a vulnerability

Use a private [GitHub Security Advisory](https://github.com/Raymer8639/neoproot/security/advisories/new)
to report a vulnerability. Do not publish exploit details, proof-of-concept
code, or other sensitive details in public issues, discussions, or pull
requests before a fix is available.

Include the neoproot version, CPU architecture, host system, rootfs,
command line, complete reproduction steps, and enough output to reproduce the
problem. Maintainers will respond on a best-effort basis and coordinate a fix
or disclosure through the advisory.

## Isolation limitations

neoproot, like PRoot, uses ptrace to emulate chroot/root. It **does not provide
kernel-level isolation** and must not be used as a security boundary for
untrusted users or root filesystems.

See the [Termux security policy](https://termux.dev/security) for host-level
guidance.
