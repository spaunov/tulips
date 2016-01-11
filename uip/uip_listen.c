#include "uip.h"

void
uip_listen(uip_t uip, uint16_t port) {
  for(uint16_t c = 0; c < UIP_LISTENPORTS; ++c) {
    if(uip->listenports[c] == 0) {
      uip->listenports[c] = port;
      return;
    }
  }
}

