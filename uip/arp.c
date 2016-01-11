/**
 * \addtogroup uip
 * @{
 */

/**
 * \defgroup uiparp uIP Address Resolution Protocol
 * @{
 *
 * The Address Resolution Protocol ARP is used for mapping between IP
 * addresses and link level addresses such as the Ethernet MAC
 * addresses. ARP uses broadcast queries to ask for the link level
 * address of a known IP address and the host which is configured with
 * the IP address for which the query was meant, will respond with its
 * link level address.
 *
 * \note This ARP implementation only supports Ethernet.
 */

/**
 * \file
 * Implementation of the ARP Address Resolution Protocol.
 * \author Adam Dunkels <adam@dunkels.com>
 *
 */

/*
 * Copyright (c) 2001-2003, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 * $Id: uip_arp.c,v 1.8 2006/06/02 23:36:21 adam Exp $
 *
 */

#include "arp.h"
#include <string.h>

struct arp_hdr {
  struct uip_eth_hdr ethhdr;
  uint16_t hwtype;
  uint16_t protocol;
  uint8_t hwlen;
  uint8_t protolen;
  uint16_t opcode;
  uip_macaddr_t shwaddr;
  uint16_t sipaddr[2];
  uip_macaddr_t dhwaddr;
  uint16_t dipaddr[2];
} __attribute__((packed));

struct ethip_hdr {
  struct uip_eth_hdr ethhdr;
  /* IP header. */
  uint8_t vhl,
          tos,
          len[2],
          ipid[2],
          ipoffset[2],
          ttl,
          proto;
  uint16_t ipchksum;
  uint16_t srcipaddr[2],
           destipaddr[2];
} __attribute__((packed));

#define ARP_REQUEST 1
#define ARP_REPLY   2
#define ARP_HWTYPE_ETH 1

#define BUF(uip)   ((struct arp_hdr *)&uip->buf[0])
#define IPBUF(uip) ((struct ethip_hdr *)&uip->buf[0])

static const uip_macaddr_t broadcast_ethaddr = {{0xff,0xff,0xff,0xff,0xff,0xff}};
static const uint16_t broadcast_ipaddr[2] = {0xffff,0xffff};

/*-----------------------------------------------------------------------------------*/
/**
 * Initialize the ARP module.
 *
 */
/*-----------------------------------------------------------------------------------*/
void
uip_arp_init(uip_arp_t arp)
{
  memset(arp, 0, sizeof(struct uip_arp));
}
/*-----------------------------------------------------------------------------------*/
/**
 * Periodic ARP processing function.
 *
 * This function performs periodic timer processing in the ARP module
 * and should be called at regular intervals. The recommended interval
 * is 10 seconds between the calls.
 *
 */
  /*-----------------------------------------------------------------------------------*/
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
/*-----------------------------------------------------------------------------------*/
static void
uip_arp_update(uip_arp_t arp, uint16_t *ipaddr, uip_macaddr_t *ethaddr)
{
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
/*-----------------------------------------------------------------------------------*/
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
  /*-----------------------------------------------------------------------------------*/
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
/*-----------------------------------------------------------------------------------*/
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
    /*-----------------------------------------------------------------------------------*/
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
/*-----------------------------------------------------------------------------------*/
/**
 * Prepend Ethernet header to an outbound IP packet and see if we need
 * to send out an ARP request.
 *
 * This function should be called before sending out an IP packet. The
 * function checks the destination IP address of the IP packet to see
 * what Ethernet MAC address that should be used as a destination MAC
 * address on the Ethernet.
 *
 * If the destination IP address is in the local network (determined
 * by logical ANDing of netmask and our IP address), the function
 * checks the ARP cache to see if an entry for the destination IP
 * address is found. If so, an Ethernet header is prepended and the
 * function returns. If no ARP cache entry is found for the
 * destination IP address, the packet in the uip_buf[] is replaced by
 * an ARP request packet for the IP address. The IP packet is dropped
 * and it is assumed that they higher level protocols (e.g., TCP)
 * eventually will retransmit the dropped packet.
 *
 * If the destination IP address is not on the local network, the IP
 * address of the default router is used instead.
 *
 * When the function returns, a packet is present in the uip_buf[]
 * buffer, and the length of the packet is in the global variable
 * uip->len.
 */
/*-----------------------------------------------------------------------------------*/
void
uip_arp_out(uip_t uip, uip_arp_t arp)
{
  uint16_t ipaddr[2];
  struct arp_entry *tabptr;

  /* Find the destination IP address in the ARP table and construct
     the Ethernet header. If the destination IP addres isn't on the
     local network, we use the default router's IP address instead.

     If not ARP table entry is found, we overwrite the original IP
     packet with an ARP request for the IP address. */

  /* First check if destination is a local broadcast. */
  if(uip_ipaddr_cmp(IPBUF(uip)->destipaddr, broadcast_ipaddr)) {
    memcpy(IPBUF(uip)->ethhdr.dest.addr, broadcast_ethaddr.addr, 6);
  } else {
    /* Check if the destination address is on the local network. */
    if(!uip_ipaddr_maskcmp(IPBUF(uip)->destipaddr, uip->hostaddr, uip->netmask)) {
      /* Destination address was not on the local network, so we need to
         use the default router's IP address instead of the destination
         address when determining the MAC address. */
      uip_ipaddr_copy(ipaddr, uip->draddr);
    } else {
      /* Else, we use the destination IP address. */
      uip_ipaddr_copy(ipaddr, IPBUF(uip)->destipaddr);
    }
    uint8_t i;
    for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
      tabptr = &arp->table[i];
      if(uip_ipaddr_cmp(ipaddr, tabptr->ipaddr)) {
        break;
      }
    }

    if(i == UIP_ARPTAB_SIZE) {
      /* The destination address was not in our ARP table, so we
         overwrite the IP packet with an ARP request. */

      memset(BUF(uip)->ethhdr.dest.addr, 0xff, 6);
      memset(BUF(uip)->dhwaddr.addr, 0x00, 6);
      memcpy(BUF(uip)->ethhdr.src.addr, uip->ethaddr.addr, 6);
      memcpy(BUF(uip)->shwaddr.addr, uip->ethaddr.addr, 6);

      uip_ipaddr_copy(BUF(uip)->dipaddr, ipaddr);
      uip_ipaddr_copy(BUF(uip)->sipaddr, uip->hostaddr);
      BUF(uip)->opcode = HTONS(ARP_REQUEST); /* ARP request. */
      BUF(uip)->hwtype = HTONS(ARP_HWTYPE_ETH);
      BUF(uip)->protocol = HTONS(UIP_ETHTYPE_IP);
      BUF(uip)->hwlen = 6;
      BUF(uip)->protolen = 4;
      BUF(uip)->ethhdr.type = HTONS(UIP_ETHTYPE_ARP);

      uip->appdata = &uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN];

      uip->len = sizeof(struct arp_hdr);
      return;
    }

    /* Build an ethernet header. */
    memcpy(IPBUF(uip)->ethhdr.dest.addr, tabptr->ethaddr.addr, 6);
  }
  memcpy(IPBUF(uip)->ethhdr.src.addr, uip->ethaddr.addr, 6);
  IPBUF(uip)->ethhdr.type = HTONS(UIP_ETHTYPE_IP);
  uip->len += sizeof(struct uip_eth_hdr);
}
/*-----------------------------------------------------------------------------------*/

/** @} */
/** @} */
