#include "uip.h"

#if !UIP_ARCH_CHKSUM
uint16_t
chksum(uint16_t sum, const uint8_t *data, uint16_t len) {
  uint16_t t;
  const uint8_t *dataptr;
  const uint8_t *last_byte;

  dataptr = data;
  last_byte = data + len - 1;

  while(dataptr < last_byte) {  /* At least two more bytes */
    t = (dataptr[0] << 8) + dataptr[1];
    sum += t;
    if(sum < t) {
      sum++;    /* carry */
    }
    dataptr += 2;
  }

  if(dataptr == last_byte) {
    t = (dataptr[0] << 8) + 0;
    sum += t;
    if(sum < t) {
      sum++;    /* carry */
    }
  }

  /* Return sum in host byte order. */
  return sum;
}
#endif
