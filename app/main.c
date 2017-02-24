#include "tapdev.h"
#include "webclient.h"
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <uip/arp.h>
#include <uip/timer.h>
#include <uip/uip.h>

#define BUF(uip) ((struct uip_eth_hdr *)&uip->buf[0])

int main(void)
{
  int i;
  uip_t uip = (uip_t)memalign(64, sizeof(struct uip));
  uip_arp_t arp = (uip_arp_t)memalign(64, sizeof(struct uip_arp));
  uip_ipaddr_t ipaddr;
  struct timer periodic_timer, arp_timer;

  clock_init();
  timer_set(&periodic_timer, 2 * CLOCK_SECOND / 2);
  timer_set(&arp_timer, CLOCK_SECOND * 10);

  tapdev_init();
  uip_init(uip);
  uip_arp_init(arp);

  uip_ipaddr(ipaddr, 10, 1, 0, 2);
  uip_sethostaddr(uip, ipaddr);
  uip_ipaddr(ipaddr, 10, 1, 0, 1);
  uip_setdraddr(uip, ipaddr);
  uip_ipaddr(ipaddr, 255,255,255,0);
  uip_setnetmask(uip, ipaddr);

  webclient_init();
  webclient_get(uip, "172.16.55.137", 8000, "/");

  while(1) {
    if(tapdev_read(uip) > 0) {
      if(BUF(uip)->type == htons(UIP_ETHTYPE_IP)) {
        uip_arp_ipin(uip, arp);
        uip_input(uip);
        /*
         * If the above function invocation resulted in
         * data that should be sent out on the network,
         * the global variable uip_len is set to a value
         * > 0.
         */
        if(uip->len > 0) {
          uip_arp_out(uip, arp);
          tapdev_send(uip);
        }
      } else if(BUF(uip)->type == htons(UIP_ETHTYPE_ARP)) {
        uip_arp_arpin(uip, arp);
        /*
         * If the above function invocation resulted in
         * data that should be sent out on the network,
         * the global variable uip_len is set to a value
         * > 0.
         */
        if(uip->len > 0) {
          tapdev_send(uip);
        }
      }
    } else if(timer_expired(&periodic_timer)) {
      timer_reset(&periodic_timer);
      for(i = 0; i < UIP_CONNS; i++) {
        uip_periodic(uip, i);
        /*
         * If the above function invocation resulted in
         * data that should be sent out on the network,
         * the global variable uip_len is set to a value
         * > 0.
         */
        if(uip->len > 0) {
          uip_arp_out(uip, arp);
          tapdev_send(uip);
        }
      }
      /*
       * Call the ARP timer function every 10 seconds.
       * */
      if(timer_expired(&arp_timer)) {
        timer_reset(&arp_timer);
        uip_arp_timer(arp);
      }
    } else for(i = 0; i < UIP_CONNS; i++) {
      uip_pollit(uip, i);
      /*
       * If the above function invocation resulted in data
       * that should be sent out on the network, the global
       * variable uip_len is set to a value > 0.
       */
      if(uip->len > 0) {
        uip_arp_out(uip, arp);
        tapdev_send(uip);
      }
    }
  }
  return 0;
}

void uip_log(char *m)
{
  printf("uIP log message: %s\n", m);
}

void webclient_closed(void)
{
  printf("Webclient: connection closed\n");
}

void webclient_aborted(void)
{
  printf("Webclient: connection aborted\n");
}

void webclient_timedout(void)
{
  printf("Webclient: connection timed out\n");
}

void webclient_connected(void)
{
  printf("Webclient: connected, waiting for data...\n");
}

void webclient_datahandler(char *data, uint16_t len)
{
  if (len > 0) {
    char sbuf[2048] = { 0 };
    memcpy(sbuf, data, len);
    printf("%s\n", sbuf);
  } else {
    printf("EOF\n");
    webclient_close();
  }
}
