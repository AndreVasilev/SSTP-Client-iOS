/* Linux unit-test config (overrides sstp/config.h via -Itests). */
#ifndef SSTP_CONFIG_H
#define SSTP_CONFIG_H

#define HAVE_ALLOCA 1
#define HAVE_ALLOCA_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_FCNTL_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMSET 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_STRING_H 1
#define HAVE_STRNCASECMP 1
#define HAVE_STRRCHR 1
#define HAVE_STRSTR 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define STDC_HEADERS 1

#define PACKAGE "sstp-client-ios-tests"
#define PACKAGE_NAME "sstp-client-ios-tests"
#define PACKAGE_VERSION "1.0.0"
#define VERSION "1.0.0"

#ifndef _PATH_TMP
#define _PATH_TMP "/tmp"
#endif

#endif
