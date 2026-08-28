#!/bin/sh
set -e

# CI hosts commonly expose /lib64 as a symlink.  Test scripts must pass
# resolved source paths to neoproot while preserving the guest destination.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

# This fixture forces basic_test.sh and advanced_test.sh down their Linux
# runtime-binding path.  Termux has no host /usr, /lib, or /lib64 tree, so
# there is no Linux path layout to validate there.
if [ ! -d /usr ] || { [ ! -d /lib ] && [ ! -d /lib64 ]; }; then
    printf '%s\n' 'SKIP: runtime binding test requires a Linux /usr and /lib or /lib64'
    exit 125
fi

TEST_ROOT=$(mktemp -d "$PWD/.test-runtime-bindings.XXXXXX")
FAKE_PROOT="$TEST_ROOT/fake-proot"

cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT HUP INT TERM

cat > "$FAKE_PROOT" << 'EOF'
#!/bin/sh
has_runtime_bind=0
requires_runtime_bind=0
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-b" ]; then
        shift
        case "$1" in
            /lib|/lib64)
                echo "unresolved runtime bind: $1" >&2
                exit 1
                ;;
            */lib:/lib|*/lib64:/lib64)
                has_runtime_bind=1
                ;;
        esac
    fi
    case "$1" in
        cat|pwd|env)
            requires_runtime_bind=1
            ;;
    esac
    shift
done

if [ "$requires_runtime_bind" -eq 1 ] && [ "$has_runtime_bind" -ne 1 ]; then
    echo "missing resolved runtime bind" >&2
    exit 1
fi
EOF
chmod +x "$FAKE_PROOT"

PREFIX= TMPDIR="$TEST_ROOT" PROOT="$FAKE_PROOT" sh ./basic_test.sh
PREFIX= TMPDIR="$TEST_ROOT" PROOT="$FAKE_PROOT" sh ./advanced_test.sh
