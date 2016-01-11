#include "arp.h"
#include <string.h>

void
uip_arp_update(uip_arp_t arp, uint16_t *ipaddr, uip_macaddr_t *ethaddr) {
  register struct arp_entry *tabptr;
  /* Walk through the ARP mapping table and try to find an entry to
     update. If none is found, the IP -> MAC address mapping is
     inserted in the ARP table. */
  for(uint8_t i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp->table[i];
    /* Only check those entries that are actually in use. */
    if(tabptr->ipaddr[0] != 0 && tabptr->ipaddr[1] != 0) {
      /* Check if the source IP address of the incoming packet matches
         the IP address in this ARP table entry. */
      if(ipaddr[0] == tabptr->ipaddr[0] && ipaddr[1] == tabptr->ipaddr[1]) {
        /* An old entry found, update this and return. */
        memcpy(tabptr->ethaddr.addr, ethaddr->addr, 6);
        tabptr->time = arp->time;
        return;
      }
    }
  }

  /* If we get here, no existing ARP table entry was found, so we
     create one. */

  /* First, we try to find an unused entry in the ARP table. */
  uint8_t i;
  for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp->table[i];
    if(tabptr->ipaddr[0] == 0 &&
       tabptr->ipaddr[1] == 0) {
      break;
    }
  }

  /* If no unused entry is found, we try to find the oldest entry and
     throw it away. */
  if(i == UIP_ARPTAB_SIZE) {
    uint8_t tmpage = 0;
    uint8_t c = 0;
    for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
      tabptr = &arp->table[i];
      if(arp->time - tabptr->time > tmpage) {
        tmpage = arp->time - tabptr->time;
        c = i;
      }
    }
    i = c;
    tabptr = &arp->table[i];
  }

  /* Now, i is the ARP table entry which we will fill with the new
     information. */
  memcpy(tabptr->ipaddr, ipaddr, 4);
  memcpy(tabptr->ethaddr.addr, ethaddr->addr, 6);
  tabptr->time = arp->time;
}

