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
#include "arch.h"

#define BUF(uip)  ((struct uip_tcpip_hdr *)&uip->buf[UIP_LLH_LEN])
#define ICMPBUF(uip)  ((struct uip_icmpip_hdr *)&uip->buf[UIP_LLH_LEN])

static const uip_ipaddr_t all_zeroes_addr = {0x0000,0x0000};

static void uip_add_rcv_nxt(uip_t uip, uint16_t n) {
	uip_add32(uip, uip->conn->rcv_nxt, n);
	uip->conn->rcv_nxt[0] = uip->acc32[0];
	uip->conn->rcv_nxt[1] = uip->acc32[1];
	uip->conn->rcv_nxt[2] = uip->acc32[2];
	uip->conn->rcv_nxt[3] = uip->acc32[3];
}

void uip_process(uip_t uip, uint8_t flag) {
	uint8_t opt = 0;
	uint16_t c = 0, tmp16 = 0;
	register struct uip_conn *uip_connr = uip->conn;
	uip->sappdata = uip->appdata = &uip->buf[UIP_IPTCPH_LEN + UIP_LLH_LEN];
	/*
	 * Check if we were invoked because of a poll request for a
	 * particular connection.
	 */
	if(flag == UIP_POLL_REQUEST) {
		if((uip_connr->tcpstateflags & UIP_TS_MASK) == UIP_ESTABLISHED &&
		   !uip_outstanding(uip_connr)) {
			uip->flags = UIP_REQ_POLL;
			app_callback(uip);
			goto appsend;
		}
		goto drop;
	}
	/*
	 * Check if we were invoked because of the perodic timer fireing.
	 */
	else if(flag == UIP_TIMER) {
		/*
		 * Increase the initial sequence number.
		 */
		if(++uip->iss[3] == 0) {
			if(++uip->iss[2] == 0) {
				if(++uip->iss[1] == 0) {
					++uip->iss[0];
				}
			}
		}
		/*
		 * Reset the length variables.
		 */
		uip->len = 0;
		uip->slen = 0;
		/*
		 * Check if the connection is in a state in which we simply wait
		 * for the connection to time out. If so, we increase the
		 * connection's timer and remove the connection if it times out.
		 */
		if(uip_connr->tcpstateflags == UIP_TIME_WAIT ||
		   uip_connr->tcpstateflags == UIP_FIN_WAIT_2) {
			++(uip_connr->timer);
			if(uip_connr->timer == UIP_TIME_WAIT_TIMEOUT) {
				uip_connr->tcpstateflags = UIP_CLOSED;
			}
		} else if(uip_connr->tcpstateflags != UIP_CLOSED) {
			/*
			 * If the connection has outstanding data, we increase
			 * the connection's timer and see if it has reached the
			 * RTO value in which case we retransmit.
			 */
			if(uip_outstanding(uip_connr)) {
				if(uip_connr->timer-- == 0) {
					if(uip_connr->nrtx == UIP_MAXRTX ||
					   ((uip_connr->tcpstateflags == UIP_SYN_SENT ||
					     uip_connr->tcpstateflags == UIP_SYN_RCVD) &&
					    uip_connr->nrtx == UIP_MAXSYNRTX)) {
						uip_connr->tcpstateflags = UIP_CLOSED;
						/*
						 * We call app_callback(uip) with uip->flags set to UIP_TIMEDOUT to
						 * inform the application that the connection has timed out.
						 */
						uip->flags = UIP_TIMEDOUT;
						app_callback(uip);
						/*
						 * We also send a reset packet to the remote host.
						 */
						BUF(uip)->flags = TCP_RST | TCP_ACK;
						goto tcp_send_nodata;
					}
					/*
					 * Exponential backoff.
					 */
					uip_connr->timer = UIP_RTO << (uip_connr->nrtx > 4?  4: uip_connr->nrtx);
					++(uip_connr->nrtx);
					/*
					 * Ok, so we need to retransmit. We do this differently depending on
					 * which state we are in. In ESTABLISHED, we call upon the application
					 * so that it may prepare the data for the retransmit. In SYN_RCVD, we
					 * resend the SYNACK that we sent earlier and in LAST_ACK we have to
					 * retransmit our FINACK.
					 */
					UIP_STAT(++uip->stat.tcp.rexmit);
					switch(uip_connr->tcpstateflags & UIP_TS_MASK) {
					case UIP_SYN_RCVD: {
						/*
						 * In the SYN_RCVD state, we should retransmit our SYNACK.
						 */
						goto tcp_send_synack;
					}
					case UIP_SYN_SENT: {
						/*
						 * In the SYN_SENT state, we retransmit out SYN.
						 */
						BUF(uip)->flags = 0;
						goto tcp_send_syn;
					}
					case UIP_ESTABLISHED: {
						/*
						 * In the ESTABLISHED state, we call upon the application to do the
						 * actual retransmit after which we jump into the code for sending
						 * out the packet (the apprexmit label).
						 */
						uip->flags = UIP_REXMIT;
						app_callback(uip);
						goto apprexmit;
					}
					case UIP_FIN_WAIT_1:
					case UIP_CLOSING:
					case UIP_LAST_ACK: {
						/*
						 * In all these states we should retransmit a FINACK.
						 */
						goto tcp_send_finack;
					}
					}
				}
			}
			/*
			 * If there was no need for a retransmission, we poll
			 * the application for new data.
			 */
			else if((uip_connr->tcpstateflags & UIP_TS_MASK) == UIP_ESTABLISHED) {
				uip->flags = UIP_CLK_POLL;
				app_callback(uip);
				goto appsend;
			}
		}
		goto drop;
	}
	/*
	 * This is where the input processing starts.
	 */
	UIP_STAT(++uip->stat.ip.recv);
	/*
	 * Start of IP input header processing code.
	 * Check validity of the IP header.
	 */
	if(BUF(uip)->vhl != 0x45) {
		UIP_STAT(++uip->stat.ip.drop);
		UIP_STAT(++uip->stat.ip.vhlerr);
		UIP_LOG("ip: invalid version or header length.");
		goto drop;
	}
	/*
	 * Check the size of the packet. If the size reported to us in uip->len
	 * is smaller the size reported in the IP header, we assume that the
	 * packet has been corrupted in transit. If the size of uip->len is
	 * larger than the size reported in the IP packet header, the packet has
	 * been padded and we set uip->len to the correct value.
	 */
	if((BUF(uip)->len[0] << 8) + BUF(uip)->len[1] <= uip->len) {
		uip->len = (BUF(uip)->len[0] << 8) + BUF(uip)->len[1];
	} else {
		UIP_LOG("ip: packet shorter than reported in IP header.");
		goto drop;
	}
	/*
	 * Check the fragment flag.
	 */
	if((BUF(uip)->ipoffset[0] & 0x3f) != 0 || BUF(uip)->ipoffset[1] != 0) {
		UIP_STAT(++uip->stat.ip.drop);
		UIP_STAT(++uip->stat.ip.fragerr);
		UIP_LOG("ip: fragment dropped.");
		goto drop;
	}
	if(uip_ipaddr_cmp(uip->hostaddr, all_zeroes_addr)) {
		UIP_LOG("ip: packet dropped since no address assigned.");
		goto drop;
	}
	/*
	 * Check if the packet is destined for our IP address.
	 */
	else if(!uip_ipaddr_cmp(BUF(uip)->destipaddr, uip->hostaddr)) {
		UIP_STAT(++uip->stat.ip.drop);
		goto drop;
	}
	/*
	 * Compute and check the IP header checksum.
	 */
	if(uip_ipchksum(uip) != 0xffff) {
		UIP_STAT(++uip->stat.ip.drop);
		UIP_STAT(++uip->stat.ip.chkerr);
		UIP_LOG("ip: bad checksum.");
		goto drop;
	}
	/*
	 * Check for TCP packet. If so, proceed with TCP input processing.
	 */
	if(BUF(uip)->proto == UIP_PROTO_TCP) {
		goto tcp_input;
	}
	/*
	 * ICMPv4 processing code follows. We only allow ICMP packets from here.
	 */
	if(BUF(uip)->proto != UIP_PROTO_ICMP) {
		UIP_STAT(++uip->stat.ip.drop);
		UIP_STAT(++uip->stat.ip.protoerr);
		UIP_LOG("ip: neither tcp nor icmp.");
		goto drop;
	}
	UIP_STAT(++uip->stat.icmp.recv);
	/*
	 * ICMP echo (i.e., ping) processing. This is simple, we only change the
	 * ICMP type from ECHO to ECHO_REPLY and adjust the ICMP checksum before we
	 * return the packet.
	 */
	if(ICMPBUF(uip)->type != ICMP_ECHO) {
		UIP_STAT(++uip->stat.icmp.drop);
		UIP_STAT(++uip->stat.icmp.typeerr);
		UIP_LOG("icmp: not icmp echo.");
		goto drop;
	}
	ICMPBUF(uip)->type = ICMP_ECHO_REPLY;
	if(ICMPBUF(uip)->icmpchksum >= HTONS(0xffff - (ICMP_ECHO << 8))) {
		ICMPBUF(uip)->icmpchksum += HTONS(ICMP_ECHO << 8) + 1;
	} else {
		ICMPBUF(uip)->icmpchksum += HTONS(ICMP_ECHO << 8);
	}
	/*
	 * Swap IP addresses.
	 */
	uip_ipaddr_copy(BUF(uip)->destipaddr, BUF(uip)->srcipaddr);
	uip_ipaddr_copy(BUF(uip)->srcipaddr, uip->hostaddr);
	UIP_STAT(++uip->stat.icmp.sent);
	goto send;
	/*
	 * End of IPv4 input header processing code.
	 */

tcp_input:

	UIP_STAT(++uip->stat.tcp.recv);

	/*
	 * Start of TCP input header processing code.
	 * Compute and check the TCP checksum.
	 */
	if(uip_tcpchksum(uip) != 0xffff) {
		UIP_STAT(++uip->stat.tcp.drop);
		UIP_STAT(++uip->stat.tcp.chkerr);
		UIP_LOG("tcp: bad checksum.");
		goto drop;
	}
	/*
	 * Demultiplex this segment.
	 * First check any active connections.
	 */
	for(uip_connr = &uip->conns[0]; uip_connr <= &uip->conns[UIP_CONNS - 1];
		++uip_connr) {
		if(uip_connr->tcpstateflags != UIP_CLOSED &&
			BUF(uip)->destport == uip_connr->lport &&
			BUF(uip)->srcport == uip_connr->rport &&
			uip_ipaddr_cmp(BUF(uip)->srcipaddr, uip_connr->ripaddr)) {
			goto found;
		}
	}
	/*
	 * If we didn't find and active connection that expected the packet,
	 * either this packet is an old duplicate, or this is a SYN packet
	 * destined for a connection in LISTEN. If the SYN flag isn't set, it is
	 * an old packet and we send a RST.
	 */
	if((BUF(uip)->flags & TCP_CTL) != TCP_SYN) {
		goto reset;
	}
	tmp16 = BUF(uip)->destport;
	/*
	 * Next, check listening connections.
	 */
	for(uint16_t c = 0; c < UIP_LISTENPORTS; ++c) {
		if(tmp16 == uip->listenports[c])
			goto found_listen;
	}
	/*
	 * No matching connection found, so we send a RST packet.
	 */
	UIP_STAT(++uip->stat.tcp.synrst);

reset:

	/*
	 * We do not send resets in response to resets.
	 */
	if(BUF(uip)->flags & TCP_RST) {
		goto drop;
	}
	UIP_STAT(++uip->stat.tcp.rst);
	BUF(uip)->flags = TCP_RST | TCP_ACK;
	uip->len = UIP_IPTCPH_LEN;
	BUF(uip)->tcpoffset = 5 << 4;
	/*
	 * Flip the seqno and ackno fields in the TCP header.
	 */
	c = BUF(uip)->seqno[3];
	BUF(uip)->seqno[3] = BUF(uip)->ackno[3];
	BUF(uip)->ackno[3] = c;
	c = BUF(uip)->seqno[2];
	BUF(uip)->seqno[2] = BUF(uip)->ackno[2];
	BUF(uip)->ackno[2] = c;
	c = BUF(uip)->seqno[1];
	BUF(uip)->seqno[1] = BUF(uip)->ackno[1];
	BUF(uip)->ackno[1] = c;
	c = BUF(uip)->seqno[0];
	BUF(uip)->seqno[0] = BUF(uip)->ackno[0];
	BUF(uip)->ackno[0] = c;
	/*
	 * We also have to increase the sequence number we are acknowledging. If
	 * the least significant byte overflowed, we need to propagate the carry
	 * to the other bytes as well.
	 */
	if(++BUF(uip)->ackno[3] == 0) {
		if(++BUF(uip)->ackno[2] == 0) {
			if(++BUF(uip)->ackno[1] == 0) {
				++BUF(uip)->ackno[0];
			}
		}
	}
	/*
	 * Swap port numbers.
	 */
	tmp16 = BUF(uip)->srcport;
	BUF(uip)->srcport = BUF(uip)->destport;
	BUF(uip)->destport = tmp16;
	/*
	 * Swap IP addresses.
	 */
	uip_ipaddr_copy(BUF(uip)->destipaddr, BUF(uip)->srcipaddr);
	uip_ipaddr_copy(BUF(uip)->srcipaddr, uip->hostaddr);
	/*
	 * And send out the RST packet!
	 */
	goto tcp_send_noconn;
	/*
	 * This label will be jumped to if we matched the incoming packet with a
	 * connection in LISTEN. In that case, we should create a new connection
	 * and send a SYNACK in return.
	 */

found_listen:

	/*
	 * First we check if there are any connections avaliable. Unused
	 * connections are kept in the same table as used connections, but
	 * unused ones have the tcpstate set to CLOSED. Also, connections in
	 * TIME_WAIT are kept track of and we'll use the oldest one if no
	 * CLOSED connections are found. Thanks to Eddie C. Dost for a very
	 * nice algorithm for the TIME_WAIT search.
	 */
	uip_connr = 0;
	for(uint16_t c = 0; c < UIP_CONNS; ++c) {
		if(uip->conns[c].tcpstateflags == UIP_CLOSED) {
			uip_connr = &uip->conns[c];
			break;
		}
		if(uip->conns[c].tcpstateflags == UIP_TIME_WAIT) {
			if(uip_connr == 0 ||
			   uip->conns[c].timer > uip_connr->timer) {
				uip_connr = &uip->conns[c];
			}
		}
	}
	/*
	 * All connections are used already, we drop packet and hope that the
	 * remote end will retransmit the packet at a time when we have more
	 * spare connections.
	 */
	if(uip_connr == 0) {
		UIP_STAT(++uip->stat.tcp.syndrop);
		UIP_LOG("tcp: found no unused connections.");
		goto drop;
	}
	uip->conn = uip_connr;
	/*
	 * Fill in the necessary fields for the new connection.
	 */
	uip_connr->rto = uip_connr->timer = UIP_RTO;
	uip_connr->sa = 0;
	uip_connr->sv = 4;
	uip_connr->nrtx = 0;
	uip_connr->lport = BUF(uip)->destport;
	uip_connr->rport = BUF(uip)->srcport;
	uip_ipaddr_copy(uip_connr->ripaddr, BUF(uip)->srcipaddr);
	uip_connr->tcpstateflags = UIP_SYN_RCVD;
	uip_connr->snd_nxt[0] = uip->iss[0];
	uip_connr->snd_nxt[1] = uip->iss[1];
	uip_connr->snd_nxt[2] = uip->iss[2];
	uip_connr->snd_nxt[3] = uip->iss[3];
	uip_connr->len = 1;
	/*
	 * rcv_nxt should be the seqno from the incoming packet + 1.
	 */
	uip_connr->rcv_nxt[3] = BUF(uip)->seqno[3];
	uip_connr->rcv_nxt[2] = BUF(uip)->seqno[2];
	uip_connr->rcv_nxt[1] = BUF(uip)->seqno[1];
	uip_connr->rcv_nxt[0] = BUF(uip)->seqno[0];
	uip_add_rcv_nxt(uip, 1);
	/*
	 * Parse the TCP MSS option, if present.
	 */
	if((BUF(uip)->tcpoffset & 0xf0) > 0x50) {
		for(uint16_t c = 0; c < ((BUF(uip)->tcpoffset >> 4) - 5) << 2 ;) {
			opt = uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + c];
			if(opt == TCP_OPT_END) {
				/*
				 * End of options.
				 */
				break;
			} else if(opt == TCP_OPT_NOOP) {
				++c;
				/*
				 * NOP option.
				 */
			} else if(opt == TCP_OPT_MSS &&
				  uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c] == TCP_OPT_MSS_LEN) {
				/*
				 * An MSS option with the right option length.
				 */
				tmp16 = ((uint16_t)uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 2 + c] << 8) |
					(uint16_t)uip->buf[UIP_IPTCPH_LEN + UIP_LLH_LEN + 3 + c];
				uip_connr->initialmss = uip_connr->mss =
					tmp16 > UIP_TCP_MSS? UIP_TCP_MSS: tmp16;
				/*
				 * And we are done processing options.
				 */
				break;
			} else {
				/*
				 * All other options have a length field, so that we easily
				 * can skip past them.
				 */
				if(uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c] == 0) {
					/*
					 * If the length field is zero, the options are malformed and we don't
					 * process them further.
					 */
					break;
				}
				c += uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c];
			}
		}
	}
	/*
	 * Our response will be a SYNACK.
	 */

tcp_send_synack:

	BUF(uip)->flags = TCP_ACK;

tcp_send_syn:

	BUF(uip)->flags |= TCP_SYN;

	/*
	 * We send out the TCP Maximum Segment Size option with our SYNACK.
	 */
	BUF(uip)->optdata[0] = TCP_OPT_MSS;
	BUF(uip)->optdata[1] = TCP_OPT_MSS_LEN;
	BUF(uip)->optdata[2] = (UIP_TCP_MSS) / 256;
	BUF(uip)->optdata[3] = (UIP_TCP_MSS) & 255;
	uip->len = UIP_IPTCPH_LEN + TCP_OPT_MSS_LEN;
	BUF(uip)->tcpoffset = ((UIP_TCPH_LEN + TCP_OPT_MSS_LEN) / 4) << 4;
	goto tcp_send;
	/*
	 * This label will be jumped to if we found an active connection.
	 */

found:

	uip->conn = uip_connr;
	uip->flags = 0;
	/*
	 * We do a very naive form of TCP reset processing; we just accept any
	 * RST and kill our connection. We should in fact check if the sequence
	 * number of this reset is wihtin our advertised window before we accept
	 * the reset.
	 */
	if(BUF(uip)->flags & TCP_RST) {
		uip_connr->tcpstateflags = UIP_CLOSED;
		UIP_LOG("tcp: got reset, aborting connection.");
		uip->flags = UIP_ABORT;
		app_callback(uip);
		goto drop;
	}
	/*
	 * Calculated the length of the data, if the application has sent
	 * any data to us.
	 */
	c = (BUF(uip)->tcpoffset >> 4) << 2;
	/*
	 * uip->len will contain the length of the actual TCP data. This is
	 * calculated by subtracing the length of the TCP header (in c) and the
	 * length of the IP header (20 bytes).
	 */
	uip->len = uip->len - c - UIP_IPH_LEN;
	/*
	 * First, check if the sequence number of the incoming packet is what
	 * we're expecting next. If not, we send out an ACK with the correct
	 * numbers in.
	 */
	if(!(((uip_connr->tcpstateflags & UIP_TS_MASK) == UIP_SYN_SENT) &&
		((BUF(uip)->flags & TCP_CTL) == (TCP_SYN | TCP_ACK)))) {
		if((uip->len > 0 || ((BUF(uip)->flags & (TCP_SYN | TCP_FIN)) != 0)) &&
			(BUF(uip)->seqno[0] != uip_connr->rcv_nxt[0] ||
			BUF(uip)->seqno[1] != uip_connr->rcv_nxt[1] ||
			BUF(uip)->seqno[2] != uip_connr->rcv_nxt[2] ||
			BUF(uip)->seqno[3] != uip_connr->rcv_nxt[3])) {
			goto tcp_send_ack;
		}
	}
	/*
	 * Next, check if the incoming segment acknowledges any outstanding
	 * data. If so, we update the sequence number, reset the length of
	 * the outstanding data, calculate RTT estimations, and reset the
	 * retransmission timer.
	 */
	if((BUF(uip)->flags & TCP_ACK) && uip_outstanding(uip_connr)) {
		uip_add32(uip, uip_connr->snd_nxt, uip_connr->len);
		if(BUF(uip)->ackno[0] == uip->acc32[0] &&
		   BUF(uip)->ackno[1] == uip->acc32[1] &&
		   BUF(uip)->ackno[2] == uip->acc32[2] &&
		   BUF(uip)->ackno[3] == uip->acc32[3]) {
			/*
			 * Update sequence number.
			 */
			uip_connr->snd_nxt[0] = uip->acc32[0];
			uip_connr->snd_nxt[1] = uip->acc32[1];
			uip_connr->snd_nxt[2] = uip->acc32[2];
			uip_connr->snd_nxt[3] = uip->acc32[3];
			/*
			 * Do RTT estimation, unless we have done retransmissions.
			 */
			if(uip_connr->nrtx == 0) {
				signed char m;
				m = uip_connr->rto - uip_connr->timer;
				/*
				 * This is taken directly from VJs original code
				 * in his paper
				 */
				m = m - (uip_connr->sa >> 3);
				uip_connr->sa += m;
				if(m < 0) {
					m = -m;
				}
				m = m - (uip_connr->sv >> 2);
				uip_connr->sv += m;
				uip_connr->rto = (uip_connr->sa >> 3) + uip_connr->sv;
			}
			/*
			 * Set the acknowledged flag.
			 */
			uip->flags = UIP_ACKDATA;
			/*
			 * Reset the retransmission timer.
			 */
			uip_connr->timer = uip_connr->rto;
			/*
			 * Reset length of outstanding data.
			 */
			uip_connr->len = 0;
		}
	}
	/*
	 * Do different things depending on in what state the connection is.
	 * CLOSED and LISTEN are not handled here. CLOSE_WAIT is not
	 * implemented, since we force the application to close when the peer
	 * sends a FIN (hence the application goes directly from ESTABLISHED to
	 * LAST_ACK).
	 */
	switch(uip_connr->tcpstateflags & UIP_TS_MASK) {
	/*
	 * In SYN_RCVD we have sent out a SYNACK in response to a SYN,
	 * and we are waiting for an ACK that acknowledges the data we
	 * sent out the last time. Therefore, we want to have the
	 * UIP_ACKDATA flag set. If so, we enter the ESTABLISHED state.
	 */
	case UIP_SYN_RCVD: {
		if(uip->flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_ESTABLISHED;
			uip->flags = UIP_CONNECTED;
			uip_connr->len = 0;
			if(uip->len > 0) {
				uip->flags |= UIP_NEWDATA;
				uip_add_rcv_nxt(uip, uip->len);
			}
			uip->slen = 0;
			app_callback(uip);
			goto appsend;
		}
		goto drop;
	}
	/*
	 * In SYN_SENT, we wait for a SYNACK that is sent in response to
	 * our SYN.  The rcv_nxt is set to sequence number in the SYNACK
	 * plus one, and we send an ACK. We move into the ESTABLISHED
	 * state.
	 */
	case UIP_SYN_SENT: {
		if((uip->flags & UIP_ACKDATA) &&
		   (BUF(uip)->flags & TCP_CTL) == (TCP_SYN | TCP_ACK)) {
			/*
			 * Parse the TCP MSS option, if present.
			 */
			if((BUF(uip)->tcpoffset & 0xf0) > 0x50) {
				for(uint16_t c = 0; c < ((BUF(uip)->tcpoffset >> 4) - 5) << 2 ;) {
					opt = uip->buf[UIP_IPTCPH_LEN + UIP_LLH_LEN + c];
					if(opt == TCP_OPT_END) {
						/*
						 * End of options.
						 */
						break;
					} else if(opt == TCP_OPT_NOOP) {
						++c;
						/*
						 * NOP option.
						 */
					} else if(opt == TCP_OPT_MSS &&
						  uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c] == TCP_OPT_MSS_LEN) {
						/*
						 * An MSS option with the right option length.
						 */
						tmp16 = (uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 2 + c] << 8) |
							uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 3 + c];
						uip_connr->initialmss =
							uip_connr->mss = tmp16 > UIP_TCP_MSS? UIP_TCP_MSS: tmp16;
						/*
						 * And we are done processing options.
						 */
						break;
					} else {
						/*
						 * All other options have a length field, so that we easily can
						 * skip past them.
						 */
						if(uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c] == 0) {
							/*
							 * If the length field is zero, the options are malformed and we
							 * don't process them further.
							 */
							break;
						}
						c += uip->buf[UIP_TCPIP_HLEN + UIP_LLH_LEN + 1 + c];
					}
				}
			}
			uip_connr->tcpstateflags = UIP_ESTABLISHED;
			uip_connr->rcv_nxt[0] = BUF(uip)->seqno[0];
			uip_connr->rcv_nxt[1] = BUF(uip)->seqno[1];
			uip_connr->rcv_nxt[2] = BUF(uip)->seqno[2];
			uip_connr->rcv_nxt[3] = BUF(uip)->seqno[3];
			uip_add_rcv_nxt(uip, 1);
			uip->flags = UIP_CONNECTED | UIP_NEWDATA;
			uip_connr->len = 0;
			uip->len = 0;
			uip->slen = 0;
			app_callback(uip);
			goto appsend;
		}
		/*
		 * Inform the application that the connection failed
		 */
		uip->flags = UIP_ABORT;
		app_callback(uip);
		/*
		 * The connection is closed after we send the RST
		 */
		uip->conn->tcpstateflags = UIP_CLOSED;
		goto reset;
	}
	/*
	 * In the ESTABLISHED state, we call upon the application to feed data
	 * into the uip->buf. If the UIP_ACKDATA flag is set, the application
	 * should put new data into the buffer, otherwise we are retransmitting
	 * an old segment, and the application should put that data into the
	 * buffer.  If the incoming packet is a FIN, we should close the
	 * connection on this side as well, and we send out a FIN and enter the
	 * LAST_ACK state. We require that there is no outstanding data;
	 * otherwise the sequence numbers will be screwed up.
	 */
	case UIP_ESTABLISHED: {
		if(BUF(uip)->flags & TCP_FIN && !(uip_connr->tcpstateflags & UIP_STOPPED)) {
			if(uip_outstanding(uip_connr)) {
				goto drop;
			}
			uip_add_rcv_nxt(uip, 1 + uip->len);
			uip->flags |= UIP_CLOSE;
			if(uip->len > 0) {
				uip->flags |= UIP_NEWDATA;
			}
			app_callback(uip);
			uip_connr->len = 1;
			uip_connr->tcpstateflags = UIP_LAST_ACK;
			uip_connr->nrtx = 0;

tcp_send_finack:

			BUF(uip)->flags = TCP_FIN | TCP_ACK;
			goto tcp_send_nodata;
		}
		/*
		 * Check the URG flag. If this is set, the segment carries
		 * urgent data that we must pass to the application.
		 */
		if((BUF(uip)->flags & TCP_URG) != 0) {
#if UIP_URGDATA > 0
			uip_urglen = (BUF(uip)->urgp[0] << 8) | BUF(uip)->urgp[1];
			if(uip_urglen > uip->len) {
				/* There is more urgent data in the next segment to come. */
				uip_urglen = uip->len;
			}
			uip_add_rcv_nxt(uip_urglen);
			uip->len -= uip_urglen;
			uip_urgdata = uip_appdata;
			uip_appdata += uip_urglen;
		} else {
			uip_urglen = 0;
#else /* UIP_URGDATA > 0 */
			uip->appdata = ((char *)uip->appdata) + ((BUF(uip)->urgp[0] << 8) | BUF(uip)->urgp[1]);
			uip->len -= (BUF(uip)->urgp[0] << 8) | BUF(uip)->urgp[1];
#endif /* UIP_URGDATA > 0 */
		}
		/*
		 * If uip->len > 0 we have TCP data in the packet, and we flag
		 * this by setting the UIP_NEWDATA flag and update the sequence
		 * number we acknowledge. If the application has stopped the
		 * dataflow using uip_stop(), we must not accept any data
		 * packets from the remote host.
		 */
		if(uip->len > 0 && !(uip_connr->tcpstateflags & UIP_STOPPED)) {
			uip->flags |= UIP_NEWDATA;
			uip_add_rcv_nxt(uip, uip->len);
		}
		/*
		 * Check if the available buffer space advertised by the other
		 * end is smaller than the initial MSS for this connection. If
		 * so, we set the current MSS to the window size to ensure that
		 * the application does not send more data than the other end
		 * can handle.
		 *
		 * If the remote host advertises a zero window, we set the MSS
		 * to the initial MSS so that the application will send an
		 * entire MSS of data. This data will not be acknowledged by the
		 * receiver, and the application will retransmit it. This is
		 * called the "persistent timer" and uses the retransmission
		 * mechanim.
		 */
		tmp16 = ((uint16_t)BUF(uip)->wnd[0] << 8) + (uint16_t)BUF(uip)->wnd[1];
		if(tmp16 > uip_connr->initialmss ||
		   tmp16 == 0) {
			tmp16 = uip_connr->initialmss;
		}
		uip_connr->mss = tmp16;
		/*
		 * If this packet constitutes an ACK for outstanding data
		 * (flagged by the UIP_ACKDATA flag, we should call the
		 * application since it might want to send more data. If the
		 * incoming packet had data from the peer (as flagged by the
		 * UIP_NEWDATA flag), the application must also be notified.
		 *
		 * When the application is called, the global variable uip->len
		 * contains the length of the incoming data. The application can
		 * access the incoming data through the global pointer
		 * uip_appdata, which usually points UIP_IPTCPH_LEN +
		 * UIP_LLH_LEN bytes into the uip->buf array.
		 *
		 * If the application wishes to send any data, this data should
		 * be put into the uip_appdata and the length of the data should
		 * be put into uip->len. If the application don't have any data
		 * to send, uip->len must be set to 0.
		 */
		if(uip->flags & (UIP_NEWDATA | UIP_ACKDATA)) {
			uip->slen = 0;
			app_callback(uip);

appsend:

			if(uip->flags & UIP_ABORT) {
				uip->slen = 0;
				uip_connr->tcpstateflags = UIP_CLOSED;
				BUF(uip)->flags = TCP_RST | TCP_ACK;
				goto tcp_send_nodata;
			}
			if(uip->flags & UIP_CLOSE) {
				uip->slen = 0;
				uip_connr->len = 1;
				uip_connr->tcpstateflags = UIP_FIN_WAIT_1;
				uip_connr->nrtx = 0;
				BUF(uip)->flags = TCP_FIN | TCP_ACK;
				goto tcp_send_nodata;
			}
			/*
			 * If uip->slen > 0, the application has data to be sent.
			 */
			if(uip->slen > 0) {
				/*
				 * If the connection has acknowledged data, the contents of the ->len
				 * variable should be discarded.
				 */
				if((uip->flags & UIP_ACKDATA) != 0) {
					uip_connr->len = 0;
				}
				/*
				 * If the ->len variable is non-zero the connection has already data in
				 * transit and cannot send anymore right now.
				 */
				if(uip_connr->len == 0) {
					/*
					 * The application cannot send more than what is allowed by the mss (the
					 * minumum of the MSS and the available window).
					 */
					if(uip->slen > uip_connr->mss) {
						uip->slen = uip_connr->mss;
					}
					/*
					 * Remember how much data we send out now so that we know when
					 * everything has been acknowledged.
					 */
					uip_connr->len = uip->slen;
				} else {
					/*
					 * If the application already had unacknowledged data, we make sure that
					 * the application does not send (i.e., retransmit) out more than it
					 * previously sent out.
					 */
					uip->slen = uip_connr->len;
				}
			}
			uip_connr->nrtx = 0;

apprexmit:

			uip->appdata = uip->sappdata;
			/*
			 * If the application has data to be sent, or if the incoming packet had
			 * new data in it, we must send out a packet.
			 */
			if(uip->slen > 0 && uip_connr->len > 0) {
				/*
				 * Add the length of the IP and TCP headers.
				 * */
				uip->len = uip_connr->len + UIP_TCPIP_HLEN;
				/*
				 * We always set the ACK flag in response packets.
				 */
				BUF(uip)->flags = TCP_ACK | TCP_PSH;
				/*
				 * Send the packet.
				 */
				goto tcp_send_noopts;
			}
			/*
			 * If there is no data to send, just send out a pure ACK if
			 * there is newdata.
			 */
				if(uip->flags & UIP_NEWDATA) {
					uip->len = UIP_TCPIP_HLEN;
					BUF(uip)->flags = TCP_ACK;
					goto tcp_send_noopts;
				}
		}
		goto drop;
	}
	/*
	 * We can close this connection if the peer has acknowledged our FIN. This
	 * is indicated by the UIP_ACKDATA flag.
	 */
	case UIP_LAST_ACK: {
		if(uip->flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_CLOSED;
			uip->flags = UIP_CLOSE;
			app_callback(uip);
		}
	} break;
	/*
	 * The application has closed the connection, but the remote host hasn't
	 * closed its end yet. Thus we do nothing but wait for a FIN from the other
	 * side.
	 */
	case UIP_FIN_WAIT_1: {
		if(uip->len > 0) {
			uip_add_rcv_nxt(uip, uip->len);
		}
		if(BUF(uip)->flags & TCP_FIN) {
			if(uip->flags & UIP_ACKDATA) {
				uip_connr->tcpstateflags = UIP_TIME_WAIT;
				uip_connr->timer = 0;
				uip_connr->len = 0;
			} else {
				uip_connr->tcpstateflags = UIP_CLOSING;
			}
			uip_add_rcv_nxt(uip, 1);
			uip->flags = UIP_CLOSE;
			app_callback(uip);
			goto tcp_send_ack;
		} else if(uip->flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_FIN_WAIT_2;
			uip_connr->len = 0;
			goto drop;
		}
		if(uip->len > 0) {
			goto tcp_send_ack;
		}
		goto drop;
	}
	case UIP_FIN_WAIT_2: {
		if(uip->len > 0) {
			uip_add_rcv_nxt(uip, uip->len);
		}
		if(BUF(uip)->flags & TCP_FIN) {
			uip_connr->tcpstateflags = UIP_TIME_WAIT;
			uip_connr->timer = 0;
			uip_add_rcv_nxt(uip, 1);
			uip->flags = UIP_CLOSE;
			app_callback(uip);
			goto tcp_send_ack;
		}
		if(uip->len > 0) {
			goto tcp_send_ack;
		}
		goto drop;
	}
	case UIP_TIME_WAIT: {
		goto tcp_send_ack;
	}
	case UIP_CLOSING: {
		if(uip->flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_TIME_WAIT;
			uip_connr->timer = 0;
		}
	}
	}
	goto drop;
	/*
	 * We jump here when we are ready to send the packet, and just want to set the
	 * appropriate TCP sequence numbers in the TCP header.
	 */

tcp_send_ack:

	BUF(uip)->flags = TCP_ACK;

tcp_send_nodata:

	uip->len = UIP_IPTCPH_LEN;

tcp_send_noopts:

	BUF(uip)->tcpoffset = (UIP_TCPH_LEN / 4) << 4;

tcp_send:

	/*
	 * We're done with the input processing. We are now ready to send a
	 * reply. Our job is to fill in all the fields of the TCP and IP
	 * headers before calculating the checksum and finally send the
	 * packet.
	 */
	BUF(uip)->ackno[0] = uip_connr->rcv_nxt[0];
	BUF(uip)->ackno[1] = uip_connr->rcv_nxt[1];
	BUF(uip)->ackno[2] = uip_connr->rcv_nxt[2];
	BUF(uip)->ackno[3] = uip_connr->rcv_nxt[3];

	BUF(uip)->seqno[0] = uip_connr->snd_nxt[0];
	BUF(uip)->seqno[1] = uip_connr->snd_nxt[1];
	BUF(uip)->seqno[2] = uip_connr->snd_nxt[2];
	BUF(uip)->seqno[3] = uip_connr->snd_nxt[3];

	BUF(uip)->proto = UIP_PROTO_TCP;

	BUF(uip)->srcport  = uip_connr->lport;
	BUF(uip)->destport = uip_connr->rport;

	uip_ipaddr_copy(BUF(uip)->srcipaddr, uip->hostaddr);
	uip_ipaddr_copy(BUF(uip)->destipaddr, uip_connr->ripaddr);
	/*
	 * If the connection has issued uip_stop(), we advertise a zero window so
	 * that the remote host will stop sending data.
	 */
	if(uip_connr->tcpstateflags & UIP_STOPPED) {
		BUF(uip)->wnd[0] = BUF(uip)->wnd[1] = 0;
	} else {
		BUF(uip)->wnd[0] = ((UIP_RECEIVE_WINDOW) >> 8);
		BUF(uip)->wnd[1] = ((UIP_RECEIVE_WINDOW) & 0xff);
	}

tcp_send_noconn:

	BUF(uip)->ttl = UIP_TTL;
	BUF(uip)->len[0] = (uip->len >> 8);
	BUF(uip)->len[1] = (uip->len & 0xff);

	BUF(uip)->urgp[0] = BUF(uip)->urgp[1] = 0;

	/*
	 * Calculate TCP checksum.
	 */
	BUF(uip)->tcpchksum = 0;
	BUF(uip)->tcpchksum = ~(uip_tcpchksum(uip));

	BUF(uip)->vhl = 0x45;
	BUF(uip)->tos = 0;
	BUF(uip)->ipoffset[0] = BUF(uip)->ipoffset[1] = 0;
	++uip->ipid;
	BUF(uip)->ipid[0] = uip->ipid >> 8;
	BUF(uip)->ipid[1] = uip->ipid & 0xff;
	/*
	* Calculate IP checksum.
	*/
	BUF(uip)->ipchksum = 0;
	BUF(uip)->ipchksum = ~(uip_ipchksum(uip));
	DEBUG_PRINTF("uip tcp_send_noconn: chksum 0x%04x\n", uip_ipchksum(uip));
	UIP_STAT(++uip->stat.tcp.sent);

send:

	DEBUG_PRINTF("Sending packet with length %d (%d)\n", uip->len,
			(BUF(uip)->len[0] << 8) | BUF(uip)->len[1]);

	UIP_STAT(++uip->stat.ip.sent);
	/*
	 * Return and let the caller do the actual transmission.
	 */
	uip->flags = 0;
	return;

drop:

	uip->len = 0;
	uip->flags = 0;
	return;
}
