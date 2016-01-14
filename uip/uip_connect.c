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

#include "uip.h"

struct uip_conn * uip_connect(uip_t uip, uip_ipaddr_t *ripaddr, uint16_t rport)
{
	register struct uip_conn *conn, *cconn;

again:

	/*
	 * Find an unused local port.
	 */
	++uip->lastport;
	if (uip->lastport >= 32000) {
		uip->lastport = 4096;
	}
	/*
	 * Check if this port is already in use, and if so try to find another
	 * one.
	 */
	for(uint16_t c = 0; c < UIP_CONNS; ++c) {
		conn = &uip->conns[c];
		if (conn->tcpstateflags != UIP_CLOSED &&
		   conn->lport == htons(uip->lastport)) {
			goto again;
		}
	}

	conn = 0;
	for(uint16_t c = 0; c < UIP_CONNS; ++c) {
		cconn = &uip->conns[c];
		if (cconn->tcpstateflags == UIP_CLOSED) {
			conn = cconn;
			break;
		}
		if (cconn->tcpstateflags == UIP_TIME_WAIT) {
			if (conn == 0 ||
			   cconn->timer > conn->timer) {
				conn = cconn;
			}
		}
	}

	if (conn == 0) {
		return 0;
	}

	conn->tcpstateflags = UIP_SYN_SENT;

	conn->snd_nxt[0] = uip->iss[0];
	conn->snd_nxt[1] = uip->iss[1];
	conn->snd_nxt[2] = uip->iss[2];
	conn->snd_nxt[3] = uip->iss[3];

	conn->initialmss = conn->mss = UIP_TCP_MSS;

	conn->len = 1;   /* TCP length of the SYN is one. */
	conn->nrtx = 0;
	conn->timer = 1; /* Send the SYN next time around. */
	conn->rto = UIP_RTO;
	conn->sa = 0;
	conn->sv = 16;   /* Initial value of the RTT variance. */
	conn->lport = htons(uip->lastport);
	conn->rport = rport;
	uip_ipaddr_copy(&conn->ripaddr, ripaddr);

	return conn;
}

