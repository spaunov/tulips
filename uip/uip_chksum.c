#include "uip.h"
#include "arch.h"

#if !UIP_ARCH_CHKSUM
uint16_t
uip_chksum(uint16_t *data, uint16_t len)
{
  return htons(chksum(0, (uint8_t *)data, len));
}
#endif
