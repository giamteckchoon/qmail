#include <sys/types.h>
#include <sys/stat.h>
#include "readwrite.h"
#include "sig.h"
#include "exit.h"
#include "open.h"
#include "seek.h"
#include "fmt.h"
#include "alloc.h"
#include "substdio.h"
#include "datetime.h"
#include "now.h"
#include "triggerpull.h"
#include "extra.h"
#include "auto_qmail.h"
#include "auto_uids.h"
#include "date822fmt.h"
#include "fmtqfn.h"
#include "stralloc.h"
#include "constmap.h"

#define DEATH 86400 /* 24 hours; _must_ be below q-s's OSSIFIED (36 hours) */
#define ADDR 1003

char inbuf[2048];
struct substdio ssin;
char outbuf[256];
struct substdio ssout;

int tapok = 0;
stralloc tap = {0};
struct constmap maptap;
stralloc chkaddr = {0};
int tapped;
stralloc tapaddr = {0};
stralloc controlfile = {0};

datetime_sec starttime;
struct datetime dt;
unsigned long mypid;
unsigned long uid;
char *pidfn;
struct stat pidst;
unsigned long messnum;
char *messfn;
char *todofn;
char *intdfn;
int messfd;
int intdfd;
int flagmademess = 0;
int flagmadeintd = 0;

void cleanup()
{
 if (flagmadeintd)
  {
   seek_trunc(intdfd,0);
   if (unlink(intdfn) == -1) return;
  }
 if (flagmademess)
  {
   seek_trunc(messfd,0);
   if (unlink(messfn) == -1) return;
  }
}

void die(e) int e; { _exit(e); }
void die_write() { cleanup(); die(53); }
void die_read() { cleanup(); die(54); }
void sigalrm() { /* thou shalt not clean up here */ die(52); }
void sigbug() { die(81); }

unsigned int receivedlen;
char *received;
/* "Received: (qmail-queue invoked by alias); 26 Sep 1995 04:46:54 -0000\n" */

static unsigned int receivedfmt(s)
char *s;
{
 unsigned int i;
 unsigned int len;
 len = 0;
 i = fmt_str(s,"Received: (qmail "); len += i; if (s) s += i;
 i = fmt_ulong(s,mypid); len += i; if (s) s += i;
 i = fmt_str(s," invoked "); len += i; if (s) s += i;
 if (uid == get_uid(auto_uida))
  { i = fmt_str(s,"by alias"); len += i; if (s) s += i; }
 else if (uid == get_uid(auto_uidd))
  { i = fmt_str(s,"from network"); len += i; if (s) s += i; }
 else if (uid == get_uid(auto_uids))
  { i = fmt_str(s,"for bounce"); len += i; if (s) s += i; }
 else
  {
   i = fmt_str(s,"by uid "); len += i; if (s) s += i;
   i = fmt_ulong(s,uid); len += i; if (s) s += i;
  }
 i = fmt_str(s,"); "); len += i; if (s) s += i;
 i = date822fmt(s,&dt); len += i; if (s) s += i;
 return len;
}

void received_setup()
{
 receivedlen = receivedfmt((char *) 0);
 received = alloc(receivedlen + 1);
 if (!received) die(51);
 receivedfmt(received);
}

unsigned int pidfmt(s,seq)
char *s;
unsigned long seq;
{
 unsigned int i;
 unsigned int len;

 len = 0;
 i = fmt_str(s,"pid/"); len += i; if (s) s += i;
 i = fmt_ulong(s,mypid); len += i; if (s) s += i;
 i = fmt_str(s,"."); len += i; if (s) s += i;
 i = fmt_ulong(s,starttime); len += i; if (s) s += i;
 i = fmt_str(s,"."); len += i; if (s) s += i;
 i = fmt_ulong(s,seq); len += i; if (s) s += i;
 ++len; if (s) *s++ = 0;

 return len;
}

char *fnnum(dirslash,flagsplit)
char *dirslash;
int flagsplit;
{
 char *s;

 s = alloc(fmtqfn((char *) 0,dirslash,messnum,flagsplit));
 if (!s) die(51);
 fmtqfn(s,dirslash,messnum,flagsplit);
 return s;
}

void pidopen()
{
 unsigned int len;
 unsigned long seq;

 seq = 1;
 len = pidfmt((char *) 0,seq);
 pidfn = alloc(len);
 if (!pidfn) die(51);

 for (seq = 1;seq < 10;++seq)
  {
   if (pidfmt((char *) 0,seq) > len) die(81); /* paranoia */
   pidfmt(pidfn,seq);
   messfd = open_excl(pidfn);
   if (messfd != -1) return;
  }

 die(63);
}

char tmp[FMT_ULONG];

void main()
{
 unsigned int len;
 char ch;

 sig_blocknone();
 umask(033);
 if (chdir(auto_qmail) == -1) die(61);
 if (chdir("queue") == -1) die(62);

 mypid = getpid();
 uid = getuid();
 starttime = now();
 datetime_tai(&dt,starttime);

 received_setup();

 sig_pipeignore();
 sig_miscignore();
 sig_alarmcatch(sigalrm);
 sig_bugcatch(sigbug);

 alarm(DEATH);

 stralloc_copys( &controlfile, auto_qmail);
 stralloc_cats( &controlfile, "/control/taps");
 stralloc_0( &controlfile);
 tapok = control_readfile(&tap,controlfile.s,0);
 if (tapok == -1) die(65);
 if (!constmap_init(&maptap,tap.s,tap.len,0)) die(65);

 pidopen();
 if (fstat(messfd,&pidst) == -1) die(63);

 messnum = pidst.st_ino;
 messfn = fnnum("mess/",1);
 todofn = fnnum("todo/",1);
 intdfn = fnnum("intd/",1);

 if (link(pidfn,messfn) == -1) die(64);
 if (unlink(pidfn) == -1) die(63);
 flagmademess = 1;

 substdio_fdbuf(&ssout,write,messfd,outbuf,sizeof(outbuf));
 substdio_fdbuf(&ssin,read,0,inbuf,sizeof(inbuf));

 if (substdio_bput(&ssout,received,receivedlen) == -1) die_write();

 switch(substdio_copy(&ssout,&ssin))
  {
   case -2: die_read();
   case -3: die_write();
  }

 if (substdio_flush(&ssout) == -1) die_write();
 if (fsync(messfd) == -1) die_write();

 intdfd = open_excl(intdfn);
 if (intdfd == -1) die(65);
 flagmadeintd = 1;

 substdio_fdbuf(&ssout,write,intdfd,outbuf,sizeof(outbuf));
 substdio_fdbuf(&ssin,read,1,inbuf,sizeof(inbuf));

 if (substdio_bput(&ssout,"u",1) == -1) die_write();
 if (substdio_bput(&ssout,tmp,fmt_ulong(tmp,uid)) == -1) die_write();
 if (substdio_bput(&ssout,"",1) == -1) die_write();

 if (substdio_bput(&ssout,"p",1) == -1) die_write();
 if (substdio_bput(&ssout,tmp,fmt_ulong(tmp,mypid)) == -1) die_write();
 if (substdio_bput(&ssout,"",1) == -1) die_write();

 if (substdio_get(&ssin,&ch,1) < 1) die_read();
 if (ch != 'F') die(91);
 if (substdio_bput(&ssout,&ch,1) == -1) die_write();
 stralloc_0(&chkaddr);
 for (len = 0;len < ADDR;++len)
  {
   if ( len == 1 ) stralloc_copyb(&chkaddr, &ch,1);
   else if ( len > 1 ) stralloc_catb(&chkaddr, &ch,1);
   if (substdio_get(&ssin,&ch,1) < 1) die_read();
   if (substdio_put(&ssout,&ch,1) == -1) die_write();
   if (!ch) break;
  }
 if (len >= ADDR) die(11);

 /* check the from address */
 stralloc_0(&chkaddr);
 if (tapped == 0 && tapcheck()==1 ) {
   tapped = 1;
   if ( tapaddr.len > 0 ) {
     if (substdio_bput(&ssout,"T",1) == -1) die_write();
     if (substdio_bput(&ssout,tapaddr.s,tapaddr.len) == -1) die_write();
     if (substdio_bput(&ssout,"",1) == -1) die_write();
   }
 }

 if (substdio_bput(&ssout,QUEUE_EXTRA,QUEUE_EXTRALEN) == -1) die_write();

 for (;;)
  {
   if (substdio_get(&ssin,&ch,1) < 1) die_read();
   if (!ch) break;
   if (ch != 'T') die(91);
   if (substdio_bput(&ssout,&ch,1) == -1) die_write();
   for (len = 0;len < ADDR;++len)
    {
     if ( len == 1 ) stralloc_copyb(&chkaddr, &ch,1);
     else if ( len > 1 ) stralloc_catb(&chkaddr, &ch,1);
     if (substdio_get(&ssin,&ch,1) < 1) die_read();
     if (substdio_bput(&ssout,&ch,1) == -1) die_write();
     if (!ch) break;
    }

    /* check the to address */
    stralloc_0(&chkaddr);
    if (tapped == 0 && tapcheck()==1 ) {
      tapped = 1;
      if ( tapaddr.len > 0 ) {
        if (substdio_bput(&ssout,"T",1) == -1) die_write();
        if (substdio_bput(&ssout,tapaddr.s,tapaddr.len) == -1) die_write();
        if (substdio_bput(&ssout,"",1) == -1) die_write();
       }
     }

   if (len >= ADDR) die(11);
  }

 if (substdio_flush(&ssout) == -1) die_write();
 if (fsync(intdfd) == -1) die_write();

 if (link(intdfn,todofn) == -1) die(66);

 triggerpull();
 die(0);
}

int tapcheck()
{
  int i = 0;
  int j = 0;
  int x = 0;
  int negate = 0;
  stralloc curregex = {0};
  char tmpbuf[200];

  while (j < tap.len) {
    i = j;
    while ((tap.s[i] != ':') && (i < tap.len)) i++;
    if (tap.s[j] == '!') {
      negate = 1;
      j++;
    }
    stralloc_copys(&tapaddr, &tap.s[i+1]);

    stralloc_copyb(&curregex,tap.s + j,(i - j));
    stralloc_0(&curregex);
    x = matchregex(chkaddr.s, curregex.s, tmpbuf);

    while ((tap.s[i] != '\0') && (i < tap.len)) i++;
  
    if ((negate) && (x == 0)) {
      return 1;
    }
    if (!(negate) && (x > 0)) {
      return 1;
    }
    j = i + 1;
    negate = 0;


  }
  return 0;
}

