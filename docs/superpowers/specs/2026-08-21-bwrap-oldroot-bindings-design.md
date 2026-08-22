# Bwrap Oldroot Binding Design

**Problem:** A bwrap nested under neoproot loses an existing guest `/tmp` bind when bwrap mounts tmpfs on `/tmp` before `pivot_root`. The subsequent bwrap source check under `/oldroot/tmp` fails with `ENOENT`.

**Decision:** Model an exact-path replacement as an overlay: the active binding records the previous active binding in `covered`. Normal guest and host lookup continues to expose only the active binding. An emulated umount restores `covered`. During pivot, the exact binding that becomes the new root is not copied under `put_old`; its immediate covered binding is copied there instead.

**Alternatives rejected:** A `/tmp`-only pivot exception does not cover other bwrap mount targets. A Codex-specific source rewrite changes the client rather than restoring Linux mount semantics.

**Acceptance:** An explicit guest `/tmp` bind remains readable as `/oldroot/tmp` after bwrap creates a tmpfs root and binds a source from the original `/tmp`; ordinary bwrap operation, mountinfo tmpfs behavior, and existing security tests remain unchanged.
