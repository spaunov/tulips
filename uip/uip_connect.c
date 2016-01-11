#include "uip.h"

struct uip_conn *
uip_connect(uip_t uip, uip_ipaddr_t *ripaddr, uint16_t rport)
{
  register struct uip_conn *conn, *cconn;

again:
  /* Find an unused local port. */
  ++uip->lastport;

  if(uip->lastport >= 32000) {
    uip->lastport = 4096;
  }

  /* Check if this port is already in use, and if so try to find another one. */
  for(uint16_t c = 0; c < UIP_CONNS; ++c) {
    conn = &uip->conns[c];
    if(conn->tcpstateflags != UIP_CLOSED &&
       conn->lport == htons(uip->lastport)) {
      goto again;
    }
  }

  conn = 0;
  for(uint16_t c = 0; c < UIP_CONNS; ++c) {
    cconn = &uip->conns[c];
    if(cconn->tcpstateflags == UIP_CLOSED) {
      conn = cconn;
      break;
    }
    if(cconn->tcpstateflags == UIP_TIME_WAIT) {
      if(conn == 0 ||
         cconn->timer > conn->timer) {
        conn = cconn;
      }
    }
  }

  if(conn == 0) {
    return 0;
  }

  conn->tcpstateflags = UIP_SYN_SENT;

  conn->snd_nxt[0] = uip->iss[0];
  conn->snd_nxt[1] = uip->iss[1];
  conn->snd_nxt[2] = uip->iss[2];
  conn->snd_nxt[3] = uip->iss[3];

  conn->initialmss = conn->mss = UIP_TCP_MSS;

  conn->len = 1;   /* TCP length of the SYN is one. */
  conn->nrtx = 0;
  conn->timer = 1; /* Send the SYN next time around. */
  conn->rto = UIP_RTO;
  conn->sa = 0;
  conn->sv = 16;   /* Initial value of the RTT variance. */
  conn->lport = htons(uip->lastport);
  conn->rport = rport;
  uip_ipaddr_copy(&conn->ripaddr, ripaddr);

  return conn;
}

