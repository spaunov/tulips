#include "uip.h"
#include "arch.h"

#define BUF(uip) ((struct uip_tcpip_hdr *)&uip->buf[UIP_LLH_LEN])

#if !UIP_ARCH_IPCHKSUM
static uint16_t
upper_layer_chksum(uip_t uip, uint8_t proto) {
  uint16_t upper_layer_len;
  uint16_t sum;

  upper_layer_len = (((uint16_t)(BUF(uip)->len[0]) << 8)
                     + BUF(uip)->len[1]) - UIP_IPH_LEN;

  /* First sum pseudoheader. */

  /* IP protocol and length fields. This addition cannot carry. */
  sum = upper_layer_len + proto;
  /* Sum IP source and destination addresses. */
  sum = chksum(sum, (uint8_t *)&BUF(uip)->srcipaddr[0], 2 * sizeof(uip_ipaddr_t));

  /* Sum TCP header and data. */
  sum = chksum(sum, &uip->buf[UIP_IPH_LEN + UIP_LLH_LEN], upper_layer_len);
  return (sum == 0) ? 0xffff : htons(sum);
}

uint16_t
uip_tcpchksum(uip_t uip)
{
  return upper_layer_chksum(uip, UIP_PROTO_TCP);
}
#endif
