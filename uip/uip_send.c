#include "uip.h"
#include <string.h>

void
uip_send(uip_t uip, const void *data, int len)
{
  if(len > 0) {
    uip->slen = len;
    if(data != uip->sappdata) {
      memcpy(uip->sappdata, (data), uip->slen);
    }
  }
}

