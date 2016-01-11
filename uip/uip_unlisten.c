#include "uip.h"

void
uip_unlisten(uip_t uip, uint16_t port) {
  for(uint16_t c = 0; c < UIP_LISTENPORTS; ++c) {
    if(uip->listenports[c] == port) {
      uip->listenports[c] = 0;
      return;
    }
  }
}

