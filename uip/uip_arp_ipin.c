#include "arp.h"

#define IPBUF(uip) ((struct ethip_hdr *)&uip->buf[0])

/**
 * ARP processing for incoming IP packets
 *
 * This function should be called by the device driver when an IP
 * packet has been received. The function will check if the address is
 * in the ARP cache, and if so the ARP cache entry will be
 * refreshed. If no ARP cache entry was found, a new one is created.
 *
 * This function expects an IP packet with a prepended Ethernet header
 * in the uip_buf[] buffer, and the length of the packet in the global
 * variable uip->len.
 */
void
uip_arp_ipin(uip_t uip, uip_arp_t arp)
{
  uip->len -= sizeof(struct uip_eth_hdr);

  /* Only insert/update an entry if the source IP address of the
     incoming IP packet comes from a host on the local network. */
  if((IPBUF(uip)->srcipaddr[0] & uip->netmask[0]) !=
     (uip->hostaddr[0] & uip->netmask[0])) {
    return;
  }
  if((IPBUF(uip)->srcipaddr[1] & uip->netmask[1]) !=
     (uip->hostaddr[1] & uip->netmask[1])) {
    return;
  }
  uip_arp_update(arp, IPBUF(uip)->srcipaddr, &(IPBUF(uip)->ethhdr.src));
}

