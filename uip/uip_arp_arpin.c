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
void uip_arp_arpin(uip_t uip, uip_arp_t arp)
{
	/*
	 * Check if the incoming packet has the right size.
	 */
	if (uip->len < sizeof(struct arp_hdr)) {
		uip->len = 0;
		return;
	}
	/*
	 * Reset the size of the response.
	 */
	uip->len = 0;
	/*
	 * Process the incoming request.
	 */
	switch (BUF(uip)->opcode) {
	/*
	 * ARP request.
	 * If it asked for our address, we send out a reply.
	 */
	case HTONS(ARP_REQUEST):
		/*
		 * Skip the request if it was not meant for us.
		 */
		if (!uip_ipaddr_cmp(BUF(uip)->dipaddr, uip->hostaddr)) {
			break;
		}
		/*
		 * First, we register the one who made the request in
		 * our ARP table, since it is likely that we will do
		 * more communication with this host in the future.
		 */
		uip_arp_update(arp, BUF(uip)->sipaddr, &BUF(uip)->shwaddr);
		/*
		 * The reply opcode is 2.
		 */
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
		break;
	/*
	 * ARP reply. We insert or update the ARP table if it was meant for us.
	 */
	case HTONS(ARP_REPLY):
		/*
		 * Skip the request if it was not meant for us.
		 */
		if (!uip_ipaddr_cmp(BUF(uip)->dipaddr, uip->hostaddr)) {
			break;
		}
		/*
		 * Register the reply in the table.
		 */
		uip_arp_update(arp, BUF(uip)->sipaddr, &BUF(uip)->shwaddr);
		break;
	}
	return;
}
