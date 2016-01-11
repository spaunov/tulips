#include "uip.h"

#if !UIP_ARCH_IPCHKSUM
uint16_t
uip_ipchksum(uip_t uip)
{
  uint16_t sum;

  sum = chksum(0, &uip->buf[UIP_LLH_LEN], UIP_IPH_LEN);
  DEBUG_PRINTF("uip_ipchksum: sum 0x%04x\n", sum);
  return (sum == 0) ? 0xffff : htons(sum);
}
#endif
