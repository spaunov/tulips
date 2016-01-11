#include "arp.h"
#include <string.h>

/**
 * Periodic ARP processing function.
 *
 * This function performs periodic timer processing in the ARP module
 * and should be called at regular intervals. The recommended interval
 * is 10 seconds between the calls.
 *
 */
void
uip_arp_timer(uip_arp_t arp)
{
  struct arp_entry *tabptr;

  ++arp->time;
  for(uint8_t i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp->table[i];
    if((tabptr->ipaddr[0] | tabptr->ipaddr[1]) != 0 &&
       arp->time - tabptr->time >= UIP_ARP_MAXAGE) {
      memset(tabptr->ipaddr, 0, 4);
    }
  }
}

