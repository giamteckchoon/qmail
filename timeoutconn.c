#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ndelay.h"
#include "select.h"
#include "error.h"
#include "readwrite.h"
#include "ip.h"
#include "byte.h"
#include "timeoutconn.h"
#include "constmap.h"
#include "control.h"
#include "stralloc.h"

#ifndef BIND_SOCKET_ERROR
#define BIND_SOCKET_ERROR 1 /* 0 to ignore bind fail, 1 to tempfail and requeue */
#endif

struct ip_address iplocal;
int bindlocal = 0;

/* get current iplocal address */
int get_bind_iplocal(ip)
struct ip_address *ip;
{
  if (iplocal.d[0] || iplocal.d[1] || iplocal.d[2] || iplocal.d[3]) {
    ip->d[0] = iplocal.d[0];
    ip->d[1] = iplocal.d[1];
    ip->d[2] = iplocal.d[2];
    ip->d[3] = iplocal.d[3];
    return 1;
  }
  return 0;
}

/* change outgoing ip */
int bind_by_changeoutgoingip(s,ip,force)
int s;
struct ip_address *ip;
int force;
{
  if (!force) if (bindlocal) return 0; /* already bind so we skip it */
  if (ip->d[0] || ip->d[1] || ip->d[2] || ip->d[3]) {
    iplocal.d[0] = ip->d[0];
    iplocal.d[1] = ip->d[1];
    iplocal.d[2] = ip->d[2];
    iplocal.d[3] = ip->d[3];
    bindlocal = 1;
  }
  return 0;
}

/* Modified from http://qmail.org/local-bind */
int bind_by_bindroutes(s,ip,force)
int s;
struct ip_address *ip;
int force;
{
  if (!force) if (bindlocal) return 0; /* already bind so we skip it */
  char *ipstr, ipstring[IPFMT+1];
  int iplen;
  stralloc routes = {0};
  struct constmap bindroutes;
  char *bindroute = (char *)0;

  /* Right, do we actually have any bind routes? */
  switch(control_readfile(&routes,"control/bindroutes",0))
  {
    case 0: return 0; /* no file, no bind to worry about */
    case -1: return -2; /* buggered up somewhere, urgh! */
    case 1: if (!constmap_init(&bindroutes,routes.s,routes.len,1)) return -3;
  }

  ipstring[0] = '.'; /* "cheating", but makes the loop check easier below! */
  ipstr = ipstring+1;
  iplen = ip_fmt(ipstr,ip); /* Well, Dan seems to trust its output! */

  /* check d.d.d.d, d.d.d., d.d., d., none */
  bindroute = constmap(&bindroutes,ipstr,iplen);
  if (!bindroute) while (iplen--)  /* no worries - the lost char must be 0-9 */
    if (ipstring[iplen] == '.')
      if (bindroute = constmap(&bindroutes,ipstr,iplen)) break;
  if (!bindroute || !*bindroute) return 0; /* no bind required */
  if (!ip_scan(bindroute,&iplocal)) return -4; /* wasn't an ip returned */
  bindlocal = 1;
  return 0;
}

int timeoutconn(s,ip,port,timeout)
int s;
struct ip_address *ip;
unsigned int port;
int timeout;
{
  char ch;
  struct sockaddr_in sin;
  struct sockaddr_in salocal;
  char *x;
  fd_set wfds;
  struct timeval tv;
 
  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin_addr,4,ip);
  x = (char *) &sin.sin_port;
  x[1] = port; port >>= 8; x[0] = port;
  sin.sin_family = AF_INET;
 
  if (ndelay_on(s) == -1) return -1;
 
  /* if bindlocal is non-zero, we bind iplocal as outgoing ip instead */
  if (bindlocal && (iplocal.d[0] || iplocal.d[1] || iplocal.d[2] || iplocal.d[3])) {
    byte_zero(&salocal,sizeof(salocal));
    salocal.sin_family = AF_INET;
    byte_copy(&salocal.sin_addr,4,&iplocal);
    if (bind(s, (struct sockaddr *)&salocal,sizeof(salocal))) {
      if (BIND_SOCKET_ERROR) return errno;
    }
  }

  if (connect(s,(struct sockaddr *) &sin,sizeof(sin)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != error_inprogress) && (errno != error_wouldblock)) return -1;
 
  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;
 
  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(sin);
    if (getpeername(s,(struct sockaddr *) &sin,&dummy) == -1) {
      read(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }
 
  errno = error_timeout; /* note that connect attempt is continuing */
  return -1;
}
