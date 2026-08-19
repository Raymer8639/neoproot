if ! command -v mcookie >/dev/null || ! command -v readlink >/dev/null ||
   ! command -v ln >/dev/null; then
    exit 125;
fi

# A hard link faked by link2symlink must not be named after the file it
# is stored as in the l2s directory.  The path hiding is done on the
# arguments of syscalls, but the kernel knows the file it gave a
# descriptor on by its real name and reports it in "/proc/<PID>/fd/<FD>";
# programs resolving a path the fast way -- open(O_PATH) then readlink()
# on that link, as typescript-go and musl's realpath(3) do -- got
# "/.l2s/.l2s.<name>0001.0002" instead of the name they opened.

DIR=${TMPDIR:-/tmp}/$(mcookie).l2s
mkdir "${DIR}"
echo content > "${DIR}/original"

RESULT=$(${PROOT} -l -b /proc sh -c "ln ${DIR}/original ${DIR}/link && exec 3< ${DIR}/link && readlink /proc/self/fd/3")

if [ "${RESULT}" != "${DIR}/link" ]; then
    rm -rf "${DIR}"
    exit 1
fi

# The procfd fallback must only apply to an exact current-process fd path,
# and must disappear once the descriptor is closed.
${PROOT} -l -b /proc sh -c "
    exec 3< ${DIR}/link
    if readlink /proc/self/fd/3junk >/dev/null 2>&1; then exit 1; fi
    if readlink /proc/999999/fd/3 >/dev/null 2>&1; then exit 1; fi
    exec 3>&-
    if readlink /proc/self/fd/3 >/dev/null 2>&1; then exit 1; fi
"
if [ $? -ne 0 ]; then
    rm -rf "${DIR}"
    exit 1
fi

rm -rf "${DIR}"

# Executing an opened executable through procfd must use the tracee fd table.
MCOOKIE=$(command -v mcookie)
$PROOT -l -b /proc sh -c "exec 3< ${MCOOKIE}; /proc/self/fd/3"
if [ $? -ne 0 ]; then
    exit 1
fi
# Explicit /proc bindings must override the default host /proc passthrough.
PROC_BIND_SOURCE=$(mktemp)
printf '65534\n' > "${PROC_BIND_SOURCE}"
RESULT=$($PROOT -l -b "${PROC_BIND_SOURCE}:/proc/sys/kernel/overflowuid" cat /proc/sys/kernel/overflowuid)
rm -f "${PROC_BIND_SOURCE}"
if [ "${RESULT}" != "65534" ]; then
    exit 1
fi
exit 0
