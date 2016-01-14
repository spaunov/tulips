#include "uip.h"
#include <string.h>

void
uip_init(uip_t uip) {
  memset(uip, 0, sizeof(struct uip));
  for(uint16_t c = 0; c < UIP_LISTENPORTS; ++c) {
    uip->listenports[c] = 0;
  }
  for(uint16_t c = 0; c < UIP_CONNS; ++c) {
    uip->conns[c].tcpstateflags = UIP_CLOSED;
  }
  uip->lastport = 1024;
}

