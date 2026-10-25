/*
** Regression harness for name_unencode() -- the DNS name decoder.
** Covers the F1 fix: a cyclic compression pointer must be rejected (not chased
** forever), while a legitimate backward pointer must still decode.
**
** Run via run.sh.  Exit 0 = pass, non-zero = fail.  The cycle case is wrapped
** in a timeout by run.sh so a regression shows up as a hang, not a false pass.
*/
#include "config.h"
#include <stdio.h>
#include <string.h>
#include "mydns.h"                 /* real src/lib/mydns.h */

/* F1 attack: offset 0 -> 2 and offset 2 -> 0 is a 2-node pointer cycle. */
static int test_cycle_rejected(void)
{
    unsigned char pkt[8];
    char dest[DNS_MAXNAMELEN + 1];
    char *r;

    pkt[0] = 0xC0; pkt[1] = 0x02;          /* ptr -> offset 2 */
    pkt[2] = 0xC0; pkt[3] = 0x00;          /* ptr -> offset 0 */
    pkt[4] = 0x00;

    r = name_unencode((char *)pkt, sizeof(pkt), (char *)pkt, dest, sizeof(dest));
    if (r == NULL) {
        printf("PASS F1  cyclic compression pointer rejected\n");
        return 0;
    }
    printf("FAIL F1  cyclic pointer was NOT rejected (decoded '%s')\n", dest);
    return 1;
}

/* F1 positive: a real backward pointer (label "a" at 0, pointer at 3) decodes. */
static int test_valid_pointer(void)
{
    unsigned char pkt[8];
    char dest[DNS_MAXNAMELEN + 1];
    char *r;

    pkt[0] = 1; pkt[1] = 'a'; pkt[2] = 0;  /* "a." at offset 0 */
    pkt[3] = 0xC0; pkt[4] = 0x00;          /* ptr -> offset 0 */

    r = name_unencode((char *)pkt, sizeof(pkt), (char *)pkt + 3, dest, sizeof(dest));
    if (r && !strcmp(dest, "a.")) {
        printf("PASS F1+ valid backward pointer decodes to '%s'\n", dest);
        return 0;
    }
    printf("FAIL F1+ valid backward pointer broke (got '%s')\n", r ? dest : "<NULL>");
    return 1;
}

int main(int argc, char **argv)
{
    const char *w = argc > 1 ? argv[1] : "all";
    if (!strcmp(w, "cycle")) return test_cycle_rejected();   /* run.sh wraps this in timeout */
    if (!strcmp(w, "valid")) return test_valid_pointer();
    return test_cycle_rejected() | test_valid_pointer();
}
