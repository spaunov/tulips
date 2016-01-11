#include "arp.h"
#include <string.h>

/**
 * Initialize the ARP module.
 */
void
uip_arp_init(uip_arp_t arp)
{
  memset(arp, 0, sizeof(struct uip_arp));
}

