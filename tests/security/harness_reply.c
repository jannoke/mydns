/*
** Regression harness for reply_add_txt() in src/mydns/reply.c (F3).
** Pulls the real file in via #include to reach the static inline function;
** encode.c (name_encode) is linked in, other externs come from stubs.c.
**
** A TXT record whose data is >=127 bytes used to overflow the signed-char
** length into rdata_enlarge(), under-allocating the reply buffer. Success is
** verified by AddressSanitizer staying quiet; a regression makes it abort and
** run.sh reports FAIL.
*/
#include "config.h"
#include "named.h"
#include "../../src/mydns/reply.c"

static int test_f3_long_txt(void)
{
    TASK t; RR r; MYDNS_RR rr; int n;

    memset(&t, 0, sizeof(t)); memset(&r, 0, sizeof(r)); memset(&rr, 0, sizeof(rr));
    t.protocol = SOCK_DGRAM;
    t.no_markers = 1;                              /* keep name_encode simple */
    strcpy((char *)r.name, "x.");                  /* valid name, ends in '.' */
    rr.ttl = 60;
    for (n = 0; n < 130; n++) rr.data[n] = 'A';    /* 130-byte TXT string */
    rr.data[130] = '\0';
    r.rr = &rr;

    reply_add_txt(&t, &r);
    free(t.rdata);                                 /* allocated by rdata_enlarge() */
    printf("PASS F3  130-byte TXT encoded without buffer under-allocation\n");
    return 0;
}

int main(void) { return test_f3_long_txt(); }
