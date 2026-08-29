#!/bin/sh

: "${NEOPROOT_WAKE_LOCK_MARKER:?}"
printf '%s\n' "$$" >"$NEOPROOT_WAKE_LOCK_MARKER"
sleep 3
