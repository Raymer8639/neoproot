#!/bin/sh
#
# Embed a shell script as a C string literal.
#
#   embed-shell.sh VARIABLE FILE > header.h
#
# The guest's session loop is real shell (backend/um_session_loop.sh) because
# it runs inside the guest and has to be testable with sh -n.  This turns it
# into the C literal the supervisor appends to init.sh, escaping exactly the
# two characters that matter in a C string: backslash and double quote.
#
# awk rather than sed: the escaping rules are easier to read and there is no
# shell quoting between the pattern and the replacement.
set -eu
if [ "$#" -ne 2 ]; then
	echo "usage: embed-shell.sh VARIABLE FILE" >&2
	exit 2
fi
variable=$1
file=$2
[ -r "$file" ] || { echo "embed-shell.sh: cannot read $file" >&2; exit 1; }

awk -v variable="$variable" '
BEGIN {
	printf "/* Generated from %s; do not edit. */\n", ENVIRON["EMBED_SOURCE"]
	printf "#ifndef NEOPROOT_UM_EMBEDDED_SHELL_H\n"
	printf "#define NEOPROOT_UM_EMBEDDED_SHELL_H\n"
	printf "static const char %s[] =\n", variable
}
{
	line = $0
	gsub(/\\/, "\\\\", line)
	gsub(/"/, "\\\"", line)
	printf "    \"%s\\n\"\n", line
}
END {
	printf "    \"\";\n"
	printf "#endif\n"
}' "$file"
