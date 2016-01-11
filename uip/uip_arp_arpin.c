#include "arp.h"
#include <string.h>

#define BUF(uip) ((struct arp_hdr *)&uip->buf[0])

/**
 * ARP processing for incoming ARP packets.
 *
 * This function should be called by the device driver when an ARP
 * packet has been received. The function will act differently
 * depending on the ARP packet type: if it is a reply for a request
 * that we previously sent out, the ARP cache will be filled in with
 * the values from the ARP reply. If the incoming ARP packet is an ARP
 * request for our IP address, an ARP reply packet is created and put
 * into the uip_buf[] buffer.
 *
 * When the function returns, the value of the global variable uip->len
 * indicates whether the device driver should send out a packet or
 * not. If uip->len is zero, no packet should be sent. If uip->len is
 * non-zero, it contains the length of the outbound packet that is
 * present in the uip_buf[] buffer.
 *
 * This function expects an ARP packet with a prepended Ethernet
 * header in the uip_buf[] buffer, and the length of the packet in the
 * global variable uip->len.
 */
void
uip_arp_arpin(uip_t uip, uip_arp_t arp)
{
  if(uip->len < sizeof(struct arp_hdr)) {
    uip->len = 0;
    return;
  }
  uip->len = 0;

  switch(BUF(uip)->opcode) {
    case HTONS(ARP_REQUEST):
      /* ARP request. If it asked for our address, we send out a
         reply. */
    if(uip_ipaddr_cmp(BUF(uip)->dipaddr, uip->hostaddr)) {
      /* First, we register the one who made the request in our ARP
         table, since it is likely that we will do more communication
         with this host in the future. */
      uip_arp_update(arp, BUF(uip)->sipaddr, &BUF(uip)->shwaddr);

      /* The reply opcode is 2. */
      BUF(uip)->opcode = HTONS(2);

      memcpy(BUF(uip)->dhwaddr.addr, BUF(uip)->shwaddr.addr, 6);
      memcpy(BUF(uip)->shwaddr.addr, uip->ethaddr.addr, 6);
      memcpy(BUF(uip)->ethhdr.src.addr, uip->ethaddr.addr, 6);
      memcpy(BUF(uip)->ethhdr.dest.addr, BUF(uip)->dhwaddr.addr, 6);

      BUF(uip)->dipaddr[0] = BUF(uip)->sipaddr[0];
      BUF(uip)->dipaddr[1] = BUF(uip)->sipaddr[1];
      BUF(uip)->sipaddr[0] = uip->hostaddr[0];
      BUF(uip)->sipaddr[1] = uip->hostaddr[1];

      BUF(uip)->ethhdr.type = HTONS(UIP_ETHTYPE_ARP);
      uip->len = sizeof(struct arp_hdr);
    }
    break;
    case HTONS(ARP_REPLY):
    /* ARP reply. We insert or update the ARP table if it was meant
       for us. */
    if(uip_ipaddr_cmp(BUF(uip)->dipaddr, uip->hostaddr)) {
      uip_arp_update(arp, BUF(uip)->sipaddr, &BUF(uip)->shwaddr);
    }
    break;
  }

  return;
}

