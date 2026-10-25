#!/bin/sh
#
# Build and run the MyDNS security regression harnesses under AddressSanitizer
# + UndefinedBehaviorSanitizer. Each harness #includes the real source file
# under test, so this checks the actual shipped code, not a copy.
#
# Requirements: a C compiler (gcc or clang), libc headers, and the MySQL client
# headers (Debian/Ubuntu: default-libmysqlclient-dev). No ./configure needed --
# a minimal config.h in this directory stands in for the autotools one.
#
# Exit 0 if every check passes, non-zero otherwise.

set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CC=${CC:-gcc}
command -v "$CC" >/dev/null 2>&1 || CC=clang
command -v "$CC" >/dev/null 2>&1 || { echo "no C compiler found (set \$CC)"; exit 2; }

# MySQL client include flags (the header chain pulls in mysql.h).
if command -v mysql_config >/dev/null 2>&1; then
    MYSQL_CFLAGS=$(mysql_config --cflags)
elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists mysqlclient 2>/dev/null; then
    MYSQL_CFLAGS=$(pkg-config --cflags mysqlclient)
else
    MYSQL_CFLAGS="-I/usr/include/mysql"
fi

INC="-I$HERE -I$ROOT/lib -I$ROOT/src/lib -I$ROOT/src/mydns $MYSQL_CFLAGS"
SAN="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all"
WARN="-Wno-format"            # update.c has pre-existing %.*s/size_t format warnings

fail=0
build() {  # build <out> <extra-ldflags> <sources...>
    out=$1; ldf=$2; shift 2
    # shellcheck disable=SC2086
    if ! $CC $SAN $WARN $INC "$@" $ldf -o "$WORK/$out" 2>"$WORK/$out.log"; then
        echo "BUILD FAIL: $out"; sed 's/^/    /' "$WORK/$out.log"; fail=1; return 1
    fi
    return 0
}

echo "== building harnesses ($CC) =="
build unencode "" "$HERE/harness_unencode.c" "$ROOT/src/lib/unencode.c"
build update   "" "$HERE/harness_update.c"   "$ROOT/src/lib/unencode.c" "$HERE/stubs.c"
build reply    "-Wl,--allow-multiple-definition" \
               "$HERE/harness_reply.c" "$ROOT/src/mydns/encode.c" "$ROOT/src/lib/unencode.c" "$HERE/stubs.c"
[ "$fail" -eq 0 ] || { echo "== aborting: build errors =="; exit 1; }

echo
echo "== running checks =="
# F1 cycle: a regression would hang, so bound it with a timeout.
if command -v timeout >/dev/null 2>&1; then
    timeout 10 "$WORK/unencode" cycle; rc=$?
    [ "$rc" -eq 124 ] && { echo "FAIL F1  name_unencode HUNG on a pointer cycle (timeout)"; fail=1; }
    [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && fail=1
else
    "$WORK/unencode" cycle || fail=1
fi
"$WORK/unencode" valid || fail=1
"$WORK/update"          || fail=1
"$WORK/reply"           || fail=1

echo
if [ "$fail" -eq 0 ]; then echo "== ALL SECURITY REGRESSION CHECKS PASSED =="; else echo "== FAILURES ABOVE =="; fi
exit $fail
