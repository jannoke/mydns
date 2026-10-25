/*
** Regression harness for the DNS UPDATE packet parser in src/mydns/update.c.
** Pulls the real file in via #include so the static functions
** update_gobble_rr() (F2) and text_retrieve() (F4) are reachable; externs it
** does not exercise are satisfied by stubs.c.
**
** Correctness is checked two ways: return values (a malformed RR must be
** rejected, a valid one must parse), and AddressSanitizer -- if a regression
** reintroduces the overflow, ASAN aborts the process and run.sh reports FAIL.
*/
#include "config.h"
#include "named.h"
#include "../../src/mydns/update.c"

/* F2 attack: rdlength far larger than rr->rdata (513 bytes). Must be rejected
   (return NULL) with no heap overflow. */
static int test_f2_overflow_rejected(void)
{
    TASK t; MYDNS_SOA soa; UQRR *rr; char *src, *ret;
    static unsigned char q[65536];
    size_t qlen = sizeof(q);

    memset(&t, 0, sizeof(t)); memset(&soa, 0, sizeof(soa));
    rr = calloc(1, sizeof(UQRR));                 /* same heap shape as q->PR[n] */
    q[0] = 0x00;                                  /* owner name = root "." */
    src = (char *)q + 1;
    src[0]=0; src[1]=1;                           /* type  */
    src[2]=0; src[3]=1;                           /* class */
    src[4]=0; src[5]=0; src[6]=0; src[7]=0;       /* ttl   */
    src[8]=(60000>>8)&0xff; src[9]=60000&0xff;    /* rdlength = 60000 */
    t.query = (char *)q; t.len = qlen;

    ret = update_gobble_rr(&t, &soa, (char *)q, qlen, (char *)q, rr);
    free(rr);
    if (ret == NULL) { printf("PASS F2  oversized rdlength rejected, no overflow\n"); return 0; }
    printf("FAIL F2  oversized rdlength was accepted\n"); return 1;
}

/* F2 positive: a well-formed A RR (rdlength 4, fully present) parses. */
static int test_f2_valid(void)
{
    TASK t; MYDNS_SOA soa; UQRR *rr; char *src, *ret; int ok;
    static unsigned char q[64];
    size_t qlen;

    memset(&t, 0, sizeof(t)); memset(&soa, 0, sizeof(soa));
    rr = calloc(1, sizeof(UQRR));
    q[0]=0x00; src=(char*)q+1;
    src[0]=0;src[1]=1; src[2]=0;src[3]=1; src[4]=0;src[5]=0;src[6]=0;src[7]=60;
    src[8]=0;src[9]=4; src[10]=10;src[11]=0;src[12]=0;src[13]=1;   /* 10.0.0.1 */
    qlen = 1 + 10 + 4;
    t.query=(char*)q; t.len=qlen;

    ret = update_gobble_rr(&t, &soa, (char*)q, qlen, (char*)q, rr);
    ok = ret && rr->rdlength==4 && rr->rdata[0]==10 && rr->rdata[3]==1;
    free(rr);
    if (ok) { printf("PASS F2+ valid A RR parsed (10.0.0.1)\n"); return 0; }
    printf("FAIL F2+ valid A RR failed to parse\n"); return 1;
}

/* F4 attack: fill an exact-size destination so the terminator would land one
   byte past it on the old code. ASAN aborts here if the off-by-one returns. */
static int test_f4_offbyone(void)
{
    char dst[8];
    unsigned char src[32];
    memset(src, 'A', sizeof(src));
    src[0] = 20;                                  /* label length */
    text_retrieve((char *)src, (char *)src + sizeof(src), dst, sizeof(dst), 0);
    printf("PASS F4  no write past destination buffer\n");
    return 0;
}

/* F4 positive: a short word round-trips. */
static int test_f4_valid(void)
{
    char dst[64]; unsigned char src[8]; char *ret;
    src[0]=5; memcpy(src+1, "hello", 5);
    ret = text_retrieve((char*)src, (char*)src+6, dst, sizeof(dst), 0);
    if (ret && !strcmp(dst, "hello")) { printf("PASS F4+ 'hello' retrieved intact\n"); return 0; }
    printf("FAIL F4+ short word mangled (got '%s')\n", dst); return 1;
}

int main(void)
{
    int rc = 0;
    rc |= test_f2_overflow_rejected();
    rc |= test_f2_valid();
    rc |= test_f4_offbyone();
    rc |= test_f4_valid();
    return rc;
}
