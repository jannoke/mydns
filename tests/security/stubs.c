/*
** Link-time stubs for symbols that update.c / reply.c reference but that are
** NOT on the code paths these harnesses exercise. No MyDNS header is included
** on purpose, so the stub storage types never clash with the real
** declarations -- the linker only needs the symbols to exist. If a harness
** ever actually reaches one of these, it aborts loudly via die() so a test can
** never silently pass by exercising nothing.
*/
#include <stdio.h>
#include <stdlib.h>

static long die(const char *n) { fprintf(stderr, "STUB called (test reached an unexpected path): %s\n", n); abort(); return 0; }

/* data symbols */
void *sql = 0;
void *ZoneCache = 0, *ReplyCache = 0, *NegativeCache = 0;
char  mydns_rr_table_name[4096]  = "rr";
char  mydns_soa_table_name[4096] = "soa";
int   mydns_rr_use_active = 0;
int   mydns_soa_use_update_acl = 0;
int   tcp_enabled = 0;

/* function stubs */
long Err()                  { return die("Err"); }
long ErrSQL()               { return die("ErrSQL"); }
long WarnSQL()              { return die("WarnSQL"); }
long Verbose()              { return die("Verbose"); }
long Warnx()                { return die("Warnx"); }
/* formerr()/dnserror() ARE the expected graceful-rejection path once the
** parsers are fixed, so these return a benign error code instead of aborting. */
long _dnserror_internal()   { return -1; }
long _formerr_internal()    { return -1; }
long _sql_free()            { return die("_sql_free"); }
long _mydns_rr_free()       { return die("_mydns_rr_free"); }
long _mydns_soa_free()      { return die("_mydns_soa_free"); }
long build_reply()          { return die("build_reply"); }
long cache_purge_zone()     { return die("cache_purge_zone"); }
long clientaddr()           { return die("clientaddr"); }
long desctask()             { return die("desctask"); }
long hinfo_parse()          { return die("hinfo_parse"); }
long in_cidr()              { return die("in_cidr"); }
long mydns_qtype_str()      { return die("mydns_qtype_str"); }
long mydns_rr_load()        { return die("mydns_rr_load"); }
long mydns_soa_load()       { return die("mydns_soa_load"); }
long resolve()              { return die("resolve"); }
long rr_error()             { return die("rr_error"); }
long rrlist_free()          { return die("rrlist_free"); }
long sort_a_recs()          { return die("sort_a_recs"); }
long sort_mx_recs()         { return die("sort_mx_recs"); }
long sort_srv_recs()        { return die("sort_srv_recs"); }
long sql_escstr()           { return die("sql_escstr"); }
long sql_getrow()           { return die("sql_getrow"); }
long sql_nrquery()          { return die("sql_nrquery"); }
long sql_num_rows()         { return die("sql_num_rows"); }
long sql_query()            { return die("sql_query"); }
long sql_reopen()           { return die("sql_reopen"); }
long strtolower()           { return die("strtolower"); }
long task_output_info()     { return die("task_output_info"); }
long wildcard_match()       { return die("wildcard_match"); }
