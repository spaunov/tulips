#include "uip.h"
#include "arch.h"

#if ! UIP_ARCH_ADD32
void
uip_add32(uip_t uip, uint8_t *op32, uint16_t op16)
{
  uip->acc32[3] = op32[3] + (op16 & 0xff);
  uip->acc32[2] = op32[2] + (op16 >> 8);
  uip->acc32[1] = op32[1];
  uip->acc32[0] = op32[0];

  if(uip->acc32[2] < (op16 >> 8)) {
    ++uip->acc32[1];
    if(uip->acc32[1] == 0) {
      ++uip->acc32[0];
    }
  }
  if(uip->acc32[3] < (op16 & 0xff)) {
    ++uip->acc32[2];
    if(uip->acc32[2] == 0) {
      ++uip->acc32[1];
      if(uip->acc32[1] == 0) {
        ++uip->acc32[0];
      }
    }
  }
}
#endif /* UIP_ARCH_ADD32 */

