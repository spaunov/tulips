/**
 * \addtogroup uip
 * @{
 */

/**
 * \addtogroup uiparp
 * @{
 */

/**
 * \file
 * Macros and definitions for the ARP module.
 * \author Adam Dunkels <adam@dunkels.com>
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
 * $Id: uip_arp.h,v 1.5 2006/06/11 21:46:39 adam Exp $
 *
 */

#ifndef __UIP_ARP_H__
#define __UIP_ARP_H__

#include "uip.h"
#include <stdint.h>

/**
 * The protocol headers.
 */
struct uip_eth_hdr {
  uip_macaddr_t dest;
  uip_macaddr_t src;
  uint16_t type;
} __attribute__((packed));

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

/**
 * The ARP type.
 */

struct arp_entry {
  uint16_t ipaddr[2];
  uip_macaddr_t ethaddr;
  uint8_t time;
} __attribute__((packed));

typedef struct uip_arp {
  struct arp_entry table[UIP_ARPTAB_SIZE];
  uint8_t time;
} __attribute__((packed)) * uip_arp_t;

#define UIP_ETHTYPE_ARP 0x0806
#define UIP_ETHTYPE_IP  0x0800

/* The uip_arp_init() function must be called before any of the other
   ARP functions. */
void uip_arp_init(uip_arp_t arp);

/* The uip_arp_ipin() function should be called whenever an IP packet
   arrives from the Ethernet. This function refreshes the ARP table or
   inserts a new mapping if none exists. The function assumes that an
   IP packet with an Ethernet header is present in the uip_buf buffer
   and that the length of the packet is in the uip_len variable. */
void uip_arp_ipin(uip_t uip, uip_arp_t arp);

/* The uip_arp_arpin() should be called when an ARP packet is received
   by the Ethernet driver. This function also assumes that the
   Ethernet frame is present in the uip_buf buffer. When the
   uip_arp_arpin() function returns, the contents of the uip_buf
   buffer should be sent out on the Ethernet if the uip_len variable
   is > 0. */
void uip_arp_arpin(uip_t uip, uip_arp_t arp);

/* The uip_arp_out() function should be called when an IP packet
   should be sent out on the Ethernet. This function creates an
   Ethernet header before the IP header in the uip_buf buffer. The
   Ethernet header will have the correct Ethernet MAC destination
   address filled in if an ARP table entry for the destination IP
   address (or the IP address of the default router) is present. If no
   such table entry is found, the IP packet is overwritten with an ARP
   request and we rely on TCP to retransmit the packet that was
   overwritten. In any case, the uip_len variable holds the length of
   the Ethernet frame that should be transmitted. */
void uip_arp_out(uip_t uip, uip_arp_t arp);

/* The uip_arp_timer() function should be called every ten seconds. It
   is responsible for flushing old entries in the ARP table. */
void uip_arp_timer(uip_arp_t arp);

/**
 * Internal update function
 */
void
uip_arp_update(uip_arp_t arp, uint16_t *ipaddr, uip_macaddr_t *ethaddr);

/** @} */

/**
 * \addtogroup uipconffunc
 * @{
 */

#define ARP_REQUEST     1
#define ARP_REPLY       2
#define ARP_HWTYPE_ETH  1

/**
 * Specifiy the Ethernet MAC address.
 *
 * The ARP code needs to know the MAC address of the Ethernet card in
 * order to be able to respond to ARP queries and to generate working
 * Ethernet headers.
 *
 * \note This macro only specifies the Ethernet MAC address to the ARP
 * code. It cannot be used to change the MAC address of the Ethernet
 * card.
 *
 * \param eaddr A pointer to a struct uip_eth_addr containing the
 * Ethernet MAC address of the Ethernet card.
 *
 * \hideinitializer
 */
#define uip_setethaddr(__uip, eaddr) do { \
  uip->ethaddr.addr[0] = eaddr.addr[0];   \
  uip->ethaddr.addr[1] = eaddr.addr[1];   \
  uip->ethaddr.addr[2] = eaddr.addr[2];   \
  uip->ethaddr.addr[3] = eaddr.addr[3];   \
  uip->ethaddr.addr[4] = eaddr.addr[4];   \
  uip->ethaddr.addr[5] = eaddr.addr[5];   \
} while(0)

/** @} */
/** @} */

#endif /* __UIP_ARP_H__ */
