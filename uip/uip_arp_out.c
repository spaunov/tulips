/*
 * Copyright (c) 2004, Swedish Institute of Computer Science.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack
 *
 * Author: Adam Dunkels <adam@sics.se>
 */

#include "arp.h"
#include <string.h>

#define BUF(uip)	((struct arp_hdr *)&uip->buf[0])
#define IPBUF(uip)	((struct ethip_hdr *)&uip->buf[0])

static const uip_macaddr_t broadcast_ethaddr = {
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

static const uint16_t broadcast_ipaddr[2] = {
	0xffff, 0xffff
};

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
void uip_arp_out(uip_t uip, uip_arp_t arp)
{
	uint16_t ipaddr[2];
	struct arp_entry *tabptr;

	/*
	 * Find the destination IP address in the ARP table and construct
	 * the Ethernet header. If the destination IP addres isn't on the
	 * local network, we use the default router's IP address instead.
	 *
	 * If not ARP table entry is found, we overwrite the original IP
	 * packet with an ARP request for the IP address.
	 */

	/*
	 * First check if destination is a local broadcast.
	 */
	if (uip_ipaddr_cmp(IPBUF(uip)->destipaddr, broadcast_ipaddr)) {
		memcpy(IPBUF(uip)->ethhdr.dest.addr, broadcast_ethaddr.addr, 6);
	} else {
		/*
		 * Check if the destination address is on the local network.
		 */
		if (!uip_ipaddr_maskcmp(IPBUF(uip)->destipaddr, uip->hostaddr,
					uip->netmask)) {
			/*
			 * Destination address was not on the local network, so
			 * we need to use the default router's IP address
			 * instead of the destination address when determining
			 * the MAC address.
			 */
			uip_ipaddr_copy(ipaddr, uip->draddr);
		} else {
			/*
			 * Else, we use the destination IP address.
			 */
			uip_ipaddr_copy(ipaddr, IPBUF(uip)->destipaddr);
		}
		uint8_t i;
		for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
			tabptr = &arp->table[i];
			if (uip_ipaddr_cmp(ipaddr, tabptr->ipaddr)) {
				break;
			}
		}

		if (i == UIP_ARPTAB_SIZE) {
			/*
			 * The destination address was not in our ARP table, so
			 * we overwrite the IP packet with an ARP request.
			 */
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
		/*
		 * Write the ethernet destination address.
		 */
		memcpy(IPBUF(uip)->ethhdr.dest.addr, tabptr->ethaddr.addr, 6);
	}
	/*
	 * Write the ethernet source address.
	 */
	memcpy(IPBUF(uip)->ethhdr.src.addr, uip->ethaddr.addr, 6);
	IPBUF(uip)->ethhdr.type = HTONS(UIP_ETHTYPE_IP);
	uip->len += sizeof(struct uip_eth_hdr);
}

