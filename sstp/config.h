/* iOS Network Extension configuration for sstp-client */

#ifndef SSTP_CONFIG_H
#define SSTP_CONFIG_H

#define HAVE_ALLOCA 1
#define HAVE_ALLOCA_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_DUP2 1
#define HAVE_FCNTL_H 1
#define HAVE_GETHOSTNAME 1
#define HAVE_INTTYPES_H 1
#define HAVE_LIBEVENT 1
#define HAVE_LIBEVENT2 1
#define HAVE_LOCALTIME_R 1
#define HAVE_MALLOC 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMSET 1
#define HAVE_MKDIR 1
#define HAVE_NETDB_H 1
#define HAVE_SOCKET 1
#define HAVE_STDBOOL_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRCASECMP 1
#define HAVE_STRCHR 1
#define HAVE_STRDUP 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_STRNCASECMP 1
#define HAVE_STRRCHR 1
#define HAVE_STRSTR 1
#define HAVE_STRTOUL 1
#define HAVE_STRTOULL 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE__BOOL 1
#define STDC_HEADERS 1

/* No Linux pppd plugin / netlink / pty on iOS */
#undef HAVE_PPP_PLUGIN
#undef HAVE_NETLINK
#undef HAVE_PTY_H
#undef HAVE_FORK

#define HAVE_PATHS_H 1
#define HAVE_SYSLOG_H 1

#define PACKAGE "sstp-client-ios"
#define PACKAGE_NAME "sstp-client-ios"
#define PACKAGE_VERSION "1.0.0"
#define PACKAGE_STRING "sstp-client-ios 1.0.0"
#define VERSION "1.0.0"

#ifndef _PATH_TMP
#define _PATH_TMP "/tmp"
#endif
#ifndef _PATH_LOG
#define _PATH_LOG "/var/run/syslog"
#endif

/* Build flag used by iOS adaptations */
#ifndef SSTP_IOS
#define SSTP_IOS 1
#endif

#endif /* SSTP_CONFIG_H */
