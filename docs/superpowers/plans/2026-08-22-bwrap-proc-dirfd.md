# bwrap proc dirfd inheritance plan

## Goal

Make the inherited bwrap /proc directory fd usable after pivot_root without
regressing absolute proc path handling or neoproot virtual mountinfo.

## Steps

1. Add a deterministic mount/pivot regression for an inherited /proc fd and
   confirm the pre-fix implementation omits virtual /oldroot from mountinfo.
2. Add a path-layer predicate for a relative self/mountinfo or
   thread-self/mountinfo lookup rooted at a real /proc directory fd.
3. Route only that lookup through neoproot virtual
   /proc/<tracee-pid>/mountinfo generator. Keep a directory fd resolving
   exactly to /proc as the guest /proc base after pivot_root and a proc remount.
4. Build the Termux candidate, run the new regression and existing binding
   regressions, then run the Codex static bwrap smoke command repeatedly over
   SSH inside that one candidate neoproot instance. Never launch neoproot
   inside neoproot.
5. Update project memory and the task list. Replace the formal Termux binary
   only after the candidate passes and the user explicitly confirms deployment.
