/* Minimal private header for unit tests that only need common helpers. */
#ifndef __SSTP_PRIVATE_H__
#define __SSTP_PRIVATE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "sstp-common.h"
#include "sstp-buff.h"
#include "sstp-util.h"
#include "sstp-fcs.h"

/* Silence unused logging macros pulled by some sources */
#ifndef log_err
#define log_err(...) do { } while (0)
#define log_warn(...) do { } while (0)
#define log_info(...) do { } while (0)
#define log_debug(...) do { } while (0)
#endif

#endif
