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

#if ! UIP_ARCH_ADD32

void uip_add32(uip_t uip, uint8_t *op32, uint16_t op16)
{
  uip->acc32[3] = op32[3] + (op16 & 0xff);
  uip->acc32[2] = op32[2] + (op16 >> 8);
  uip->acc32[1] = op32[1];
  uip->acc32[0] = op32[0];

  if (uip->acc32[2] < (op16 >> 8)) {
    ++uip->acc32[1];
    if (uip->acc32[1] == 0) {
      ++uip->acc32[0];
    }
  }
  if (uip->acc32[3] < (op16 & 0xff)) {
    ++uip->acc32[2];
    if (uip->acc32[2] == 0) {
      ++uip->acc32[1];
      if (uip->acc32[1] == 0) {
        ++uip->acc32[0];
      }
    }
  }
}

#endif /* UIP_ARCH_ADD32 */

