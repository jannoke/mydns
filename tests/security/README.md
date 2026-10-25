# MyDNS security regression tests

Small AddressSanitizer harnesses that pin the four remote memory-safety / DoS
bugs fixed on the `security-hardening` branch, so they can't silently come back.
Each harness `#include`s the real source file under test, so it checks the
actual shipped parser, not a copy.

| Check | Bug | Source under test |
|-------|-----|-------------------|
| F1  | infinite loop on cyclic DNS compression pointers (DoS) | `src/lib/unencode.c` `name_unencode()` |
| F2  | heap overflow in DNS UPDATE RR parse (CVE-2007-2362) | `src/mydns/update.c` `update_gobble_rr()` |
| F3  | TXT reply buffer under-allocation (`char size = len+1`) | `src/mydns/reply.c` `reply_add_txt()` |
| F4  | off-by-one NUL write past caller buffer | `src/mydns/update.c` `text_retrieve()` |

The `F1+`/`F2+`/`F4+` checks are positive cases: they prove the fixes still
accept legitimate input.

## Running

```sh
tests/security/run.sh
```

Exit status is 0 if every check passes, non-zero otherwise (so it drops into a
CI step as-is). A reintroduced overflow aborts the process via ASAN; a
reintroduced F1 loop is caught as a `timeout`.

Requirements: a C compiler (`gcc` or `clang`), libc headers, and the MySQL
client headers (Debian/Ubuntu: `default-libmysqlclient-dev`). No `./configure`
run is needed — `config.h` here is a minimal stand-in used only for these
harnesses, and `stubs.c` satisfies the handful of link symbols the parsers
reference but that these tests don't exercise (it aborts loudly if an
unexpected path is ever reached).
