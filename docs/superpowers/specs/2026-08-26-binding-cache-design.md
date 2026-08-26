# Binding Cache Reuse Design

## Problem

Guest binding lookup allocates a BindingCache on every lookup. The cache
lookup used a parent-context search even though the cache was allocated as a
child of the file-system namespace, so the existing cache was never found.
This adds allocator work to path translation and prevents the intended prefix
index from being reused.

## Design

Store one cache pointer directly in FileSystemNameSpace. Allocate it lazily
and retain it for that namespace. Build the guest prefix index on first lookup
after bindings are available, and rebuild it lazily after any guest binding
insert or removal. Clear the cached root at the same time. Namespaces created
by CLONE_FS share the cache with their shared namespace; independent
namespaces start with an empty cache alongside their binding lists.

The cache owns only its pointer array; Binding objects remain owned by the
existing binding lists. Invalidating the array therefore does not change
binding lifetime or overlay restoration semantics.

## Verification

tests/test-binding-cache.sh enables a test-only counter and performs repeated
guest lookups. It requires exactly one cache allocation. The existing bwrap
mount and binding regressions cover dynamic binding changes and restoration.
