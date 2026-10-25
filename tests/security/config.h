/*
** Minimal hand-written config.h, used ONLY to build the security regression
** harnesses in this directory (see run.sh). It is NOT the autotools-generated
** config.h of a real build: it just defines enough HAVE_* macros, and pulls in
** <limits.h>/<netinet/in.h>, to make the mydnsutil.h / mydns.h header chain
** compile cleanly against a modern glibc + MySQL client headers without a full
** ./configure run. The harnesses exercise the pure packet parsers only.
*/
#define STDC_HEADERS         1
#define HAVE_STRING_H        1
#define HAVE_SIGNAL_H        1
#define HAVE_DECL_STRERROR   1
#define HAVE_DECL_STRCASECMP 1
#define HAVE_DECL_STRNCASECMP 1
#define HAVE_DECL_STRCOLL    1
#define HAVE_INTTYPES_H      1
#define SIZEOF_UNSIGNED_INT  4

#include <limits.h>
#include <netinet/in.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
