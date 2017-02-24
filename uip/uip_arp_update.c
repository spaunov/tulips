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

void uip_arp_update(uip_arp_t arp, uint16_t *ipaddr, uip_macaddr_t *ethaddr) {
  register struct arp_entry *tabptr;
  /*
   * Walk through the ARP mapping table and try to find an entry to
   * update. If none is found, the IP -> MAC address mapping is
   * inserted in the ARP table.
   */
  for(uint8_t i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp->table[i];
    /*
     * Only check those entries that are actually in use.
     */
    if (tabptr->ipaddr[0] != 0 && tabptr->ipaddr[1] != 0) {
      /*
       * Check if the source IP address of the incoming
       * packet matches * the IP address in this ARP table
       * entry.
       */
      if (ipaddr[0] == tabptr->ipaddr[0] &&
          ipaddr[1] == tabptr->ipaddr[1]) {
        /*
         * An old entry found, update this and return.
         */
        memcpy(tabptr->ethaddr.addr, ethaddr->addr, 6);
        tabptr->time = arp->time;
        return;
      }
    }
  }
  /*
   * If we get here, no existing ARP table entry was found,
   * so we create one.
   */

  /*
   * First, we try to find an unused entry in the ARP table.
   */
  uint8_t i;
  for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp->table[i];
    if (tabptr->ipaddr[0] == 0 &&
        tabptr->ipaddr[1] == 0) {
      break;
    }
  }
  /*
   * If no unused entry is found, we try to find the oldest entry and
   * throw it away.
   */
  if (i == UIP_ARPTAB_SIZE) {
    uint8_t tmpage = 0;
    uint8_t c = 0;
    for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
      tabptr = &arp->table[i];
      if (arp->time - tabptr->time > tmpage) {
        tmpage = arp->time - tabptr->time;
        c = i;
      }
    }
    i = c;
    tabptr = &arp->table[i];
  }
  /*
   * Now, i is the ARP table entry which we will fill with the new
   * information.
   */
  memcpy(tabptr->ipaddr, ipaddr, 4);
  memcpy(tabptr->ethaddr.addr, ethaddr->addr, 6);
  tabptr->time = arp->time;
}

