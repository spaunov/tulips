#include "uip.h"

void uip_setipid(uip_t uip, uint16_t id) {
  uip->ipid = id;
}

