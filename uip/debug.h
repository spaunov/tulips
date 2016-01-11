#ifndef __DEBUG_H__
#define __DEBUG_H__

#if UIP_LOGGING || UIP_DEBUG
#include <stdio.h>
#endif

#if UIP_LOGGING
void uip_log(char *msg);
#define UIP_LOG(m) uip_log(m)
#else
#define UIP_LOG(m)
#endif

#if UIP_DEBUG
#define DEBUG_PRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

#endif  // __DEBUG_H__
